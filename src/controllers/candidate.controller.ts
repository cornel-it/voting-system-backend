// backend/src/controllers/candidate.controller.ts

import { Request, Response, NextFunction } from 'express';
import { CandidateService } from '../services/candidate.service';
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

export class CandidateController {
  private candidateService: CandidateService;

  constructor(
    private auditService: AuditService,
    private notificationService: NotificationService
  ) {
    this.candidateService = CandidateService.getInstance();
  }

  /**
   * Create a new candidate application
   */
  async createCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const candidateData = req.body;
      const submittedBy = req.user!.id;

      // Create candidate with comprehensive validation
      const candidate = await this.candidateService.createCandidate(candidateData, submittedBy) as any;

      // Notify moderators about new candidate application
      await NotificationService.notifyModeratorsNewCandidateApplication(candidate.id);

      res.status(201).json({
        success: true,
        message: 'Candidate application submitted successfully',
        data: {
          id: candidate.id,
          studentId: candidate.studentId,
          firstName: candidate.firstName,
          lastName: candidate.lastName,
          position: candidate.position?.name,
          election: candidate.election?.title,
          status: candidate.status,
          submittedAt: candidate.createdAt
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update candidate profile
   */
  async updateCandidateProfile(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const updateData = req.body;
      const updatedBy = req.user!.id;

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Update candidate profile
      const candidate = await this.candidateService.updateCandidateProfile(id, updateData, updatedBy);

      res.json({
        success: true,
        message: 'Candidate profile updated successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload candidate photo
   */
  async uploadCandidatePhoto(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const uploadedBy = req.user!.id;

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      if (!req.file) {
        throw new AppError('Photo file is required', 400);
      }

      // Upload and process candidate photo
      const result = await this.candidateService.uploadCandidatePhoto(
        id,
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype,
        uploadedBy
      );

      res.json({
        success: true,
        message: 'Candidate photo uploaded successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidate by ID
   */
  async getCandidateById(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { useCache = 'true' } = req.query;

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Get candidate with comprehensive data
      const candidate = await this.candidateService.getCandidateById(id, useCache === 'true');

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      res.json({
        success: true,
        message: 'Candidate retrieved successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidates by election with filtering and pagination
   */
  async getCandidatesByElection(req: Request, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const {
        positionId,
        status,
        faculty,
        department,
        course,
        yearOfStudy,
        search,
        page = 1,
        limit = 50,
        useCache = 'true'
      } = req.query;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Build filters
      const filters: any = {};
      if (positionId) filters.positionId = positionId as string;
      if (status) filters.status = status as string;
      if (faculty) filters.faculty = faculty as string;
      if (department) filters.department = department as string;
      if (course) filters.course = course as string;
      if (yearOfStudy) filters.yearOfStudy = Number(yearOfStudy);
      if (search) filters.search = search as string;

      // Get candidates with filtering and pagination
      const result = await this.candidateService.getCandidatesByElection(
        electionId,
        filters,
        Number(page),
        Number(limit),
        useCache === 'true'
      );

      res.json({
        success: true,
        message: 'Candidates retrieved successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Approve candidate application (Admin/Moderator only)
   */
  async approveCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const approvedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to approve candidates', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Approve candidate
      const candidate = await this.candidateService.approveCandidate(id, approvedBy, reason) as any;

      // Send notification to candidate
      await NotificationService.notifyCandidateApproved(id, candidate.election?.title || 'Election');

      // Log approval
      await AuditService.logAction({
        action: 'CANDIDATE_APPROVED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: approvedBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          studentId: candidate.studentId,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Candidate approved successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reject candidate application (Admin/Moderator only)
   */
  async rejectCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const rejectedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to reject candidates', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Detailed reason is required (minimum 10 characters)', 400);
      }

      // Reject candidate
      const candidate = await this.candidateService.rejectCandidate(id, rejectedBy, reason) as any;

      // Send notification to candidate
      await NotificationService.notifyCandidateRejected(id, candidate.election?.title || 'Election', reason);

      // Log rejection
      await AuditService.logAction({
        action: 'CANDIDATE_REJECTED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: rejectedBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          studentId: candidate.studentId,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Candidate rejected successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Disqualify candidate (Admin only)
   */
  async disqualifyCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const disqualifiedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions - only admins can disqualify
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to disqualify candidates', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Detailed reason is required (minimum 10 characters)', 400);
      }

      // Disqualify candidate
      const candidate = await this.candidateService.disqualifyCandidate(id, disqualifiedBy, reason);

      // Log disqualification
      await AuditService.logAction({
        action: 'CANDIDATE_DISQUALIFIED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: disqualifiedBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          studentId: candidate.studentId,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Candidate disqualified successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Add running mate to candidate (Admin/Moderator only)
   */
  async addRunningMate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { runningMateId } = req.body;
      const addedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to add running mates', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      if (!runningMateId) {
        throw new AppError('Running mate candidate ID is required', 400);
      }

      // Add running mate
      const candidate = await this.candidateService.addRunningMate(id, runningMateId, addedBy) as any;

      // Log running mate addition
      await AuditService.logAction({
        action: 'RUNNING_MATE_ADDED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: addedBy,
        metadata: {
          candidateId: id,
          runningMateId,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          runningMateName: candidate.runningMate ?
            `${candidate.runningMate?.firstName} ${candidate.runningMate?.lastName}` : 'Unknown'
        }
      });

      res.json({
        success: true,
        message: 'Running mate added successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Remove running mate from candidate (Admin/Moderator only)
   */
  async removeRunningMate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const removedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to remove running mates', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Get current candidate data before removal
      const candidateBefore = await this.candidateService.getCandidateById(id, false);
      if (!candidateBefore) {
        throw new AppError('Candidate not found', 404);
      }

      // Remove running mate by updating to null
      const candidate = await this.candidateService.updateCandidateProfile(
        id,
        { runningMateId: null },
        removedBy
      );

      // Log running mate removal
      await AuditService.logAction({
        action: 'RUNNING_MATE_REMOVED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: removedBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          previousRunningMateId: candidateBefore.runningMateId
        }
      });

      res.json({
        success: true,
        message: 'Running mate removed successfully',
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidate statistics (Admin/Moderator only)
   */
  async getCandidateStats(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { electionId } = req.params;
      const { useCache = 'true' } = req.query;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view candidate statistics', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get candidate statistics
      const stats = await this.candidateService.getCandidateStats(electionId, useCache === 'true');

      res.json({
        success: true,
        message: 'Candidate statistics retrieved successfully',
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Withdraw candidate application
   */
  async withdrawCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const withdrawnBy = req.user!.id;

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Get candidate to verify ownership or admin rights
      const candidate = await this.candidateService.getCandidateById(id, false);
      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Check if user can withdraw this candidate
      const canWithdraw =
        candidate.studentId === req.user!.studentId ||
        ['ADMIN', 'SUPER_ADMIN'].includes(req.user!.role);

      if (!canWithdraw) {
        throw new AppError('You can only withdraw your own candidate application', 403);
      }

      // Withdraw candidate by updating status
      const updatedCandidate = await this.candidateService.updateCandidateStatus(
        id,
        'WITHDRAWN',
        withdrawnBy,
        reason
      );

      // Log withdrawal
      await AuditService.logAction({
        action: 'CANDIDATE_WITHDRAWN',
        category: 'CANDIDATE',
        severity: 'MEDIUM',
        userId: withdrawnBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Candidate application withdrawn successfully',
        data: updatedCandidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidates by position
   */
  async getCandidatesByPosition(req: Request, res: Response, next: NextFunction) {
    try {
      const { positionId } = req.params;
      const {
        status = 'APPROVED',
        page = 1,
        limit = 20,
        useCache = 'true'
      } = req.query;

      if (!positionId) {
        throw new AppError('Position ID is required', 400);
      }

      // Get candidates by position
      const result = await this.candidateService.getCandidatesByElection(
        '', // We'll need to get election ID from position
        { positionId, status: status as any },
        Number(page),
        Number(limit),
        useCache === 'true'
      );

      res.json({
        success: true,
        message: 'Candidates retrieved successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Search candidates across all elections (Admin/Moderator only)
   */
  async searchCandidates(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to search candidates', 403);
      }

      const {
        search,
        status,
        faculty,
        department,
        course,
        yearOfStudy,
        electionId,
        page = 1,
        limit = 50,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Build comprehensive search filters
      const filters: any = {};
      if (search) filters.search = search as string;
      if (status) filters.status = status as string;
      if (faculty) filters.faculty = faculty as string;
      if (department) filters.department = department as string;
      if (course) filters.course = course as string;
      if (yearOfStudy) filters.yearOfStudy = Number(yearOfStudy);
      if (electionId) filters.electionId = electionId as string;

      // Search candidates with advanced filtering
      const results = await this.candidateService.searchCandidates({
        ...filters,
        page: Number(page),
        limit: Number(limit),
        sortBy: sortBy as string,
        sortOrder: sortOrder as 'asc' | 'desc'
      });

      res.json({
        success: true,
        message: 'Candidate search completed successfully',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export candidates data (Admin only)
   */
  async exportCandidates(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const exportedBy = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to export candidate data', 403);
      }

      const {
        electionId,
        format = 'csv',
        status,
        includePersonalData = false,
        includeManifestos = false
      } = req.query;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Export candidates data
      const exportData = await this.candidateService.exportCandidates({
        electionId: electionId as string,
        format: format as string,
        status: status as string,
        includePersonalData: includePersonalData === 'true',
        includeManifestos: includeManifestos === 'true',
        exportedBy
      });

      // Log export operation
      await AuditService.logAction({
        action: 'CANDIDATES_EXPORTED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: exportedBy,
        metadata: {
          electionId,
          format,
          status,
          includePersonalData,
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
   * Bulk approve candidates (Admin only)
   */
  async bulkApproveCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const approvedBy = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions for bulk operations', 403);
      }

      const { candidateIds, reason } = req.body;

      if (!candidateIds || !Array.isArray(candidateIds) || candidateIds.length === 0) {
        throw new AppError('Candidate IDs array is required', 400);
      }

      if (candidateIds.length > 100) {
        throw new AppError('Cannot process more than 100 candidates at once', 400);
      }

      // Perform bulk approval
      const results = await this.candidateService.bulkApproveCandidates({
        candidateIds,
        reason,
        approvedBy
      });

      // Log bulk operation
      await AuditService.logAction({
        action: 'BULK_CANDIDATES_APPROVED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: approvedBy,
        metadata: {
          candidateCount: candidateIds.length,
          successfulApprovals: results.successful,
          failedApprovals: results.failed,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Bulk candidate approval completed',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Bulk reject candidates (Admin only)
   */
  async bulkRejectCandidate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const rejectedBy = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions for bulk operations', 403);
      }

      const { candidateIds, reason } = req.body;

      if (!candidateIds || !Array.isArray(candidateIds) || candidateIds.length === 0) {
        throw new AppError('Candidate IDs array is required', 400);
      }

      if (candidateIds.length > 100) {
        throw new AppError('Cannot process more than 100 candidates at once', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Detailed reason is required for bulk rejection (minimum 10 characters)', 400);
      }

      // Perform bulk rejection
      const results = await this.candidateService.bulkRejectCandidates({
        candidateIds,
        reason,
        rejectedBy
      });

      // Log bulk operation
      await AuditService.logAction({
        action: 'BULK_CANDIDATES_REJECTED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: rejectedBy,
        metadata: {
          candidateCount: candidateIds.length,
          successfulRejections: results.successful,
          failedRejections: results.failed,
          reason
        }
      });

      res.json({
        success: true,
        message: 'Bulk candidate rejection completed',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update candidate status (Admin only)
   */
  async updateCandidateStatus(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const { status, reason } = req.body;
      const updatedBy = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to update candidate status', 403);
      }

      if (!id) {
        throw new AppError('Candidate ID is required', 400);
      }

      // Update candidate status
      const candidate = await this.candidateService.updateCandidateStatus(id, status, updatedBy, reason);

      // Log status update
      await AuditService.logAction({
        action: `CANDIDATE_STATUS_UPDATED_TO_${status}`,
        category: 'ADMIN',
        severity: 'HIGH',
        userId: updatedBy,
        metadata: {
          candidateId: id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          oldStatus: 'UNKNOWN', // Would need to fetch before update
          newStatus: status,
          reason
        }
      });

      res.json({
        success: true,
        message: `Candidate status updated to ${status} successfully`,
        data: candidate
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidate performance analytics (Admin only)
   */
  async getCandidateAnalytics(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { electionId } = req.params;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view candidate analytics', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const {
        includeVoteAnalysis = true,
        includeDemographics = true,
        includePerformanceMetrics = true
      } = req.query;

      // Get comprehensive candidate analytics
      const analytics = await this.candidateService.getCandidateAnalytics(electionId, {
        includeVoteAnalysis: includeVoteAnalysis === 'true',
        includeDemographics: includeDemographics === 'true',
        includePerformanceMetrics: includePerformanceMetrics === 'true'
      });

      res.json({
        success: true,
        message: 'Candidate analytics retrieved successfully',
        data: analytics
      });
    } catch (error) {
      next(error);
    }
  }
}


export default  CandidateController;