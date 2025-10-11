// backend/src/controllers/result.controller.ts

import { Request, Response, NextFunction } from 'express';
import { ResultService } from '../services/result.service';
import { AuditService } from '../services/audit.service';
import { AppError } from '../utils/errors';
import { UserRole } from '@prisma/client';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
}

export class ResultController {
  private resultService: ResultService;

  constructor() {
    this.resultService = ResultService.getInstance();
  }

  /**
   * Calculate election results (Admin only)
   */
  async calculateResults(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { isDraft = true } = req.body;
      const calculatedBy = req.user!.id;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to calculate results', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const results = await this.resultService.calculateResults(electionId, calculatedBy, isDraft);

      await AuditService.logAction({
        action: 'ELECTION_RESULTS_CALCULATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: calculatedBy,
        electionId,
        metadata: {
          isDraft,
          totalVotes: results.totalVotes,
          turnoutPercentage: results.turnoutPercentage,
          positionsCount: results.positions.length
        }
      });

      res.json({
        success: true,
        message: `Election results ${isDraft ? 'calculated' : 'calculated and saved'} successfully`,
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get election results
   */
  async getElectionResults(req: Request, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { includeUnpublished = false, useCache = 'true' } = req.query;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const results = await this.resultService.getElectionResults(
        electionId,
        includeUnpublished === 'true',
        useCache === 'true'
      );

      if (!results) {
        throw new AppError('Election results not found or not available', 404);
      }

      res.json({
        success: true,
        message: 'Election results retrieved successfully',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Publish election results (Admin only)
   */
  async publishResults(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const publishedBy = req.user!.id;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to publish results', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const results = await this.resultService.publishResults(electionId, publishedBy);
      // Notification will be handled by the service internally

      res.json({
        success: true,
        message: 'Election results published successfully',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voting analytics (Admin/Moderator only)
   */
  async getVotingAnalytics(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { useCache = 'true' } = req.query;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view voting analytics', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const analytics = await this.resultService.getVotingAnalytics(electionId, useCache === 'true');

      res.json({
        success: true,
        message: 'Voting analytics retrieved successfully',
        data: analytics
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get live voting statistics
   */
  async getLiveVotingStats(req: Request, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const stats = await this.resultService.getLiveVotingStats(electionId);

      res.json({
        success: true,
        message: 'Live voting statistics retrieved successfully',
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export results data (Admin only)
   */
  async exportResults(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const {
        format = 'pdf',
        includeAnalytics = true,
        includeDemographics = true,
        includeCharts = true
      } = req.query;
      const exportedBy = req.user!.id;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to export results', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      if (!['pdf', 'csv', 'xlsx', 'json'].includes(format as string)) {
        throw new AppError('Invalid export format. Supported: pdf, csv, xlsx, json', 400);
      }

      const exportData = await this.resultService.exportResults(electionId, {
        format: format as string,
        includeAnalytics: includeAnalytics === 'true',
        includeDemographics: includeDemographics === 'true',
        includeCharts: includeCharts === 'true',
        exportedBy
      });

      await AuditService.logAction({
        action: 'ELECTION_RESULTS_EXPORTED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: exportedBy,
        electionId,
        metadata: {
          format,
          includeAnalytics,
          includeDemographics,
          includeCharts,
          exportSize: exportData.size
        }
      });

      if (format === 'json') {
        res.json({
          success: true,
          data: exportData.data
        });
      } else {
        res.setHeader('Content-Type', exportData.mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${exportData.filename}"`);
        res.send(exportData.buffer);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get position-specific results
   */
  async getPositionResults(req: Request, res: Response, next: NextFunction) {
    try {
      const { electionId, positionId } = req.params;
      const { includeDemographics = false } = req.query;

      if (!electionId || !positionId) {
        throw new AppError('Election ID and Position ID are required', 400);
      }

      const positionResults = await this.resultService.getPositionResults(
        electionId,
        positionId,
        includeDemographics === 'true'
      );

      res.json({
        success: true,
        message: 'Position results retrieved successfully',
        data: positionResults
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidate performance details (Admin only)
   */
  async getCandidatePerformance(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId, candidateId } = req.params;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view candidate performance', 403);
      }

      if (!electionId || !candidateId) {
        throw new AppError('Election ID and Candidate ID are required', 400);
      }

      const performance = await this.resultService.getCandidatePerformance(electionId, candidateId);

      res.json({
        success: true,
        message: 'Candidate performance retrieved successfully',
        data: performance
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Compare results between time periods (Admin only)
   */
  async compareResults(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { startDate, endDate, comparisonType = 'hourly' } = req.query;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to compare results', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const comparison = await this.resultService.compareResults(electionId, {
        startDate: startDate ? new Date(startDate as string) : undefined,
        endDate: endDate ? new Date(endDate as string) : undefined,
        comparisonType: comparisonType as string
      });

      res.json({
        success: true,
        message: 'Results comparison retrieved successfully',
        data: comparison
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify results integrity (Admin only)
   */
  async verifyResultsIntegrity(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const verifiedBy = req.user!.id;
      const userRole = req.user!.role;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Insufficient permissions to verify results integrity', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const verification = await this.resultService.verifyResultsIntegrity(electionId);

      await AuditService.logAction({
        action: 'RESULTS_INTEGRITY_VERIFIED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: verifiedBy,
        electionId,
        metadata: {
          integrityStatus: verification.isValid,
          checksPerformed: verification.checksPerformed,
          issuesFound: verification.issues.length
        }
      });

      res.json({
        success: true,
        message: 'Results integrity verification completed',
        data: verification
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get result summary for dashboard
   */
  async getResultSummary(req: Request, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const summary = await this.resultService.getResultSummary(electionId);

      res.json({
        success: true,
        message: 'Result summary retrieved successfully',
        data: summary
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get historical results comparison (Admin only)
   */
  async getHistoricalComparison(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { compareWith, metrics = 'all' } = req.query;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view historical comparisons', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const comparison = await this.resultService.getHistoricalComparison(electionId, {
        compareWith: compareWith as string,
        metrics: metrics as string
      });

      res.json({
        success: true,
        message: 'Historical comparison retrieved successfully',
        data: comparison
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate results certificate (Admin only)
   */
  async generateResultsCertificate(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { candidateId, certificateType = 'winner' } = req.body;
      const generatedBy = req.user!.id;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate certificates', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      const certificate = await this.resultService.generateResultsCertificate(electionId, {
        candidateId,
        certificateType,
        generatedBy
      });

      await AuditService.logAction({
        action: 'RESULTS_CERTIFICATE_GENERATED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: generatedBy,
        electionId,
        metadata: {
          candidateId,
          certificateType,
          certificateId: certificate.id
        }
      });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${certificate.filename}"`);
      res.send(certificate.buffer);
    } catch (error) {
      next(error);
    }
  }
}