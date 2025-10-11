// backend/src/controllers/vote.controller.ts

import { Request, Response, NextFunction } from 'express';
import { VoteService } from '../services/vote.service';
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

export class VoteController {
  private static instance: VoteController;
  private voteService: VoteService;
  private auditService: AuditService;
  private notificationService: NotificationService;

  private constructor() {
    this.voteService = VoteService.getInstance();
    // Import other singleton services
    const { AuditService } = require('../services/audit.service');
    const { NotificationService } = require('../services/notification.service');
    this.auditService = AuditService.getInstance();
    this.notificationService = NotificationService.getInstance();
  }

  public static getInstance(): VoteController {
    if (!VoteController.instance) {
      VoteController.instance = new VoteController();
    }
    return VoteController.instance;
  }

  /**
   * Start a new voting session
   */
  async startVotingSession(req: AuthRequest, res: Response, next: NextFunction): Promise<any> {
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
      const { electionId, deviceFingerprint } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get('user-agent') || '';

      // Validate user permissions
      if (req.user!.role !== 'VOTER') {
        throw new AppError('Only voters can start voting sessions', 403);
      }

      // Start voting session with comprehensive security
      const sessionData = await this.voteService.startVotingSession(
        userId,
        electionId,
        ipAddress || '0.0.0.0',
        userAgent,
        deviceFingerprint
      );

      return res.status(201).json({
        success: true,
        message: 'Voting session started successfully',
        data: sessionData
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * End an active voting session
   */
  async endVotingSession(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { sessionId } = req.params;
      const { reason = 'USER_ENDED' } = req.body;
      const userId = req.user!.id;

      if (!sessionId) {
        throw new AppError('Session ID is required', 400);
      }

      const result = await this.voteService.endVotingSession(sessionId, userId, reason);

      res.json({
        success: true,
        message: 'Voting session ended successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Cast votes for multiple positions in an election
   */
  async castVote(req: AuthRequest, res: Response, next: NextFunction): Promise<any> {
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
      const { sessionId, ballot, twoFactorToken } = req.body;

      // Validate required parameters
      if (!sessionId) {
        throw new AppError('Session ID is required', 400);
      }

      if (!ballot || !Array.isArray(ballot) || ballot.length === 0) {
        throw new AppError('Valid ballot is required', 400);
      }

      // Cast votes with comprehensive validation
      const result = await this.voteService.castVote(
        sessionId,
        ballot,
        userId,
        twoFactorToken
      );

      // Send vote confirmation notification
      const resultData = result as any;
      if (resultData.verificationCode && resultData.voteHash && resultData.electionId) {
        await NotificationService.sendVoteConfirmationNotification(
          userId,
          resultData.electionId,
          resultData.verificationCode,
          resultData.voteHash
        );
      }

      return res.json({
        success: true,
        message: 'Votes cast successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Complete voting session and generate receipt
   */
  async completeVotingSession(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { sessionId } = req.params;
      const userId = req.user!.id;

      if (!sessionId) {
        throw new AppError('Session ID is required', 400);
      }

      // Complete session and generate comprehensive receipt
      const receipt = await this.voteService.completeVotingSession(sessionId, userId);

      res.json({
        success: true,
        message: 'Voting session completed successfully',
        data: {
          receipt,
          verificationUrl: receipt.verificationUrl,
          receiptHash: receipt.receiptHash
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify a vote using verification code
   */
  async verifyVote(req: Request, res: Response, next: NextFunction): Promise<any> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const { verificationCode } = req.body;

      if (!verificationCode) {
        throw new AppError('Verification code is required', 400);
      }

      // Verify vote with comprehensive integrity checks
      const verification = await this.voteService.verifyVote(verificationCode);

      return res.json({
        success: true,
        message: 'Vote verification completed',
        data: verification
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voting receipt using receipt hash
   */
  async getVoteReceipt(req: Request, res: Response, next: NextFunction) {
    try {
      const { receiptHash } = req.params;

      if (!receiptHash) {
        throw new AppError('Receipt hash is required', 400);
      }

      // Get receipt with comprehensive verification
      const receipt = await this.voteService.getVoteReceipt(receiptHash);

      res.json({
        success: true,
        message: 'Receipt retrieved successfully',
        data: receipt
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voting progress for an election (Admin/Moderator only)
   */
  async getVotingProgress(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view voting progress', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get comprehensive voting progress
      const progress = await this.voteService.getVotingProgress(electionId);

      res.json({
        success: true,
        message: 'Voting progress retrieved successfully',
        data: progress
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get real-time voting statistics (Admin/Moderator only)
   */
  async getRealTimeStats(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view real-time statistics', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get real-time statistics
      const stats = await this.voteService.getRealTimeStats(electionId);

      res.json({
        success: true,
        message: 'Real-time statistics retrieved successfully',
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Tally votes for an election (Admin only)
   */
  async tallyVotes(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { includePartial = false } = req.query;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions - only admins can tally votes
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to tally votes', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Tally votes with comprehensive counting and verification
      const results = await this.voteService.tallyVotes(
        electionId,
        includePartial === 'true'
      );

      // Log vote tallying
      await AuditService.logAction({
        action: 'VOTES_TALLIED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId,
        entityType: 'Election',
        entityId: electionId,
        metadata: {
          includePartial,
          positionCount: results.results.length,
          totalVotes: results.totalVotesCast
        }
      });

      res.json({
        success: true,
        message: 'Votes tallied successfully',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get user's voting history
   */
  async getVoteHistory(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;
      const { includeDetails = false } = req.query;

      // Get comprehensive voting history
      const history = await this.voteService.getVoteHistory(
        userId,
        includeDetails === 'true'
      );

      res.json({
        success: true,
        message: 'Voting history retrieved successfully',
        data: {
          history,
          totalElections: history.length
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voting analytics for an election (Admin only)
   */
  async getVotingAnalytics(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view voting analytics', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get comprehensive voting analytics
      const analytics = await this.voteService.getVotingAnalytics(electionId);

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
   * Invalidate a vote (Admin only)
   */
  async invalidateVote(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { voteId } = req.params;
      const { reason } = req.body;
      const adminId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions - only admins can invalidate votes
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to invalidate votes', 403);
      }

      if (!voteId) {
        throw new AppError('Vote ID is required', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Detailed reason is required (minimum 10 characters)', 400);
      }

      // Invalidate vote with audit trail
      const result = await this.voteService.invalidateVote(voteId, adminId, reason);

      res.json({
        success: true,
        message: 'Vote invalidated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Check if user has voted in an election
   */
  async checkVotingStatus(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userId = req.user!.id;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Check if user has already voted
      const hasVoted = await this.voteService.hasUserVoted(userId, electionId);

      // Get active session if exists
      const activeSession = await this.voteService.getActiveSession(userId, electionId);

      res.json({
        success: true,
        data: {
          hasVoted,
          activeSession: activeSession ? {
            id: activeSession.id,
            expiresAt: activeSession.expiresAt,
            status: activeSession.status
          } : null
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get election ballot for voting
   */
  async getElectionBallot(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userId = req.user!.id;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get ballot with user eligibility check
      const ballot = await this.voteService.getElectionBallot(electionId, userId);

      res.json({
        success: true,
        message: 'Election ballot retrieved successfully',
        data: ballot
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Validate ballot before submission
   */
  async validateBallot(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId, ballot } = req.body;
      const userId = req.user!.id;

      if (!electionId || !ballot) {
        throw new AppError('Election ID and ballot are required', 400);
      }

      // Validate ballot structure and choices
      const validation = await this.voteService.validateBallotStructure(
        ballot,
        electionId,
        userId
      );

      res.json({
        success: true,
        message: 'Ballot validation completed',
        data: validation
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voting session details
   */
  async getVotingSession(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { sessionId } = req.params;
      const userId = req.user!.id;

      if (!sessionId) {
        throw new AppError('Session ID is required', 400);
      }

      // Get session with security validation
      const session = await this.voteService.getVotingSessionDetails(sessionId, userId);

      res.json({
        success: true,
        message: 'Voting session details retrieved successfully',
        data: session
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Extend voting session (if allowed)
   */
  async extendVotingSession(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { sessionId } = req.params;
      const { extensionMinutes = 15 } = req.body;
      const userId = req.user!.id;

      if (!sessionId) {
        throw new AppError('Session ID is required', 400);
      }

      if (extensionMinutes < 5 || extensionMinutes > 30) {
        throw new AppError('Extension must be between 5 and 30 minutes', 400);
      }

      // Extend session with validation
      const result = await this.voteService.extendVotingSession(
        sessionId,
        userId,
        extensionMinutes
      );

      res.json({
        success: true,
        message: 'Voting session extended successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get vote verification status
   */
  async getVerificationStatus(req: Request, res: Response, next: NextFunction) {
    try {
      const { verificationCode } = req.params;

      if (!verificationCode) {
        throw new AppError('Verification code is required', 400);
      }

      // Check verification status without full verification
      const status = await this.voteService.getVerificationStatus(verificationCode);

      res.json({
        success: true,
        message: 'Verification status retrieved successfully',
        data: status
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Report voting issue
   */
  async reportVotingIssue(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId, sessionId, issueType, description } = req.body;
      const userId = req.user!.id;

      if (!electionId || !issueType || !description) {
        throw new AppError('Election ID, issue type, and description are required', 400);
      }

      if (description.length < 20) {
        throw new AppError('Issue description must be at least 20 characters', 400);
      }

      // Report issue with comprehensive logging
      const report = await this.voteService.reportVotingIssue({
        userId,
        electionId,
        sessionId,
        issueType,
        description,
        ipAddress: req.ip || '0.0.0.0',
        userAgent: req.get('user-agent') || ''
      });

      // Send notification to admins
      await NotificationService.notifyAdminsSecurityEvent(
        'VOTING_ISSUE_REPORTED',
        {
          reportId: report.id,
          electionId,
          issueType,
          description,
          userId
        },
        'MEDIUM'
      );

      res.json({
        success: true,
        message: 'Voting issue reported successfully',
        data: {
          reportId: report.id,
          ticketNumber: (report as any).ticketNumber || 'N/A'
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get emergency voting options (for system issues)
   */
  async getEmergencyVotingOptions(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions - only admins can access emergency options
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions for emergency voting options', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Get emergency voting options
      const options = await this.voteService.getEmergencyVotingOptions(electionId);

      res.json({
        success: true,
        message: 'Emergency voting options retrieved successfully',
        data: options
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export voting data (Admin only)
   */
  async exportVotingData(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { electionId } = req.params;
      const { format = 'json', includePersonalData = false } = req.query;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to export voting data', 403);
      }

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      if (!['json', 'csv', 'xlsx'].includes(format as string)) {
        throw new AppError('Invalid export format. Supported: json, csv, xlsx', 400);
      }

      // Export voting data with comprehensive formatting
      const exportData = await this.voteService.exportVotingData(
        electionId,
        format as string,
        includePersonalData === 'true'
      );

      // Log export action
      await AuditService.logAction({
        action: 'VOTING_DATA_EXPORTED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId,
        entityType: 'Election',
        entityId: electionId,
        metadata: {
          format,
          includePersonalData,
          exportSize: exportData.size
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
}