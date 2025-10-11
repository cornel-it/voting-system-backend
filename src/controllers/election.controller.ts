// backend/src/controllers/election.controller.ts

import { Request, Response, NextFunction } from 'express';
import { electionService } from '../services/election.service';
import { NotificationService } from '../services/notification.service';
import { validationResult } from 'express-validator';
import { AppError } from '../utils/errors';
import { UserRole } from '@prisma/client';
import { prisma } from '../config/database';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
}

export class ElectionController {

  /**
   * Create a new election (Admin only)
   */
  async createElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
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
      const electionData = req.body;

      // Check admin permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user!.role)) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Create election
      const election = await electionService.createElection(
        electionData,
        userId
      );

      // Notify other admins about new election creation
      await NotificationService.notifyAdminsElectionCreated(election.id, userId);

      // Notify eligible voters about new election
      await NotificationService.notifyVotersElectionEligibility(election.id);

      // Schedule notification jobs if SCHEDULED
      if (election.status === 'SCHEDULED') {
        await electionService.scheduleElectionNotifications(election.id);
      }

      res.status(201).json({
        success: true,
        message: 'Election created successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update an election (Admin only)
   */
  async updateElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const updates = req.body;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'UPDATE'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Update election
      const election = await electionService.updateElection(id, updates, userId);

      res.json({
        success: true,
        message: 'Election updated successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete an election (Admin only)
   */
  async deleteElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      if (req.user!.role !== 'SUPER_ADMIN') {
        throw new AppError('Only super admins can delete elections', 403);
      }

      // Check if election can be deleted
      const election = await electionService.getElectionById(id);
      if (election.status === 'ACTIVE') {
        throw new AppError('Cannot delete active election', 400);
      }

      if (election.votes.length > 0) {
        throw new AppError('Cannot delete election with votes', 400);
      }

      // Delete election
      await electionService.deleteElection(id, userId);

      res.json({
        success: true,
        message: 'Election deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get all elections (with filters)
   */
  async getElections(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const {
        status,
        type,
        search,
        page = 1,
        limit = 10,
        startDate,
        endDate
      } = req.query;

      const userId = req.user?.id;
      const userRole = req.user?.role;

      // Build filters
      const filters: any = {};

      if (status) filters.status = status;
      if (type) filters.type = type;
      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);
      if (search) filters.search = search as string;

      // For non-admin users, only show eligible elections
      if (userRole === 'VOTER' && userId) {
        filters.createdById = userId; // This will be filtered in service by eligibility
      }

      // Get elections
      const result = await electionService.getAllElections(
        filters,
        Number(page),
        Number(limit)
      );

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get single election by ID
   */
  async getElectionById(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.id;

      const election = await electionService.getElectionById(id);

      // Check if user is eligible to view
      if (userId && req.user?.role === 'VOTER') {
        const eligibleElections = await electionService.getUserEligibleElections(userId);
        const isEligible = eligibleElections.some(e => e.id === id);

        if (!isEligible && election.status !== 'COMPLETED') {
          throw new AppError('You are not eligible for this election', 403);
        }
      }

      res.json({
        success: true,
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Start an election (Admin only)
   */
  async startElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'START'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Start election
      const election = await electionService.startElection(id, userId);

      // Send notifications to eligible voters
      await electionService.sendElectionNotifications(id, 'started');

      res.json({
        success: true,
        message: 'Election started successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * End an election (Admin only)
   */
  async endElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'END'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // End election
      const election = await electionService.endElection(id, userId);

      // Publish results
      await electionService.publishResults(id, userId);

      // Send result notifications
      await electionService.sendElectionNotifications(id, 'ended');

      res.json({
        success: true,
        message: 'Election ended successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Pause an election (Admin only)
   */
  async pauseElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { reason } = req.body;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'PAUSE'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Pause election
      const election = await electionService.pauseElection(id, userId, reason);

      res.json({
        success: true,
        message: 'Election paused successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resume a paused election (Admin only)
   */
  async resumeElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'RESUME'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Resume election
      const election = await electionService.resumeElection(id, userId);

      res.json({
        success: true,
        message: 'Election resumed successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get election statistics (Admin only)
   */
  async getElectionStats(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'VIEW_STATS'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      // Get statistics
      const stats = await electionService.getElectionStats(id);

      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Archive an election (Admin only)
   */
  async archiveElection(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      // Check permissions
      if (req.user!.role !== 'SUPER_ADMIN') {
        throw new AppError('Only super admins can archive elections', 403);
      }

      // Archive election
      const election = await electionService.archiveElection(id, userId);

      res.json({
        success: true,
        message: 'Election archived successfully',
        data: election
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get active elections
   */
  async getActiveElections(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const elections = await electionService.getActiveElections();

      res.json({
        success: true,
        data: elections
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get user eligible elections
   */
  async getUserEligibleElections(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;
      const elections = await electionService.getUserEligibleElections(userId);

      res.json({
        success: true,
        data: elections
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Add eligible voters
   */
  async addEligibleVoters(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { voterIds, reason } = req.body;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'MANAGE_VOTERS'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      await electionService.addEligibleVoters(id, voterIds, userId, reason);

      res.json({
        success: true,
        message: 'Eligible voters added successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Remove eligible voters
   */
  async removeEligibleVoters(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const { voterIds, reason } = req.body;
      const userId = req.user!.id;

      // Check permissions
      const hasPermission = await this.checkElectionPermission(
        id,
        userId,
        'MANAGE_VOTERS'
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      await electionService.removeEligibleVoters(id, voterIds, userId, reason);

      res.json({
        success: true,
        message: 'Eligible voters removed successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  // Helper method to check election permissions
  private async checkElectionPermission(
    electionId: string,
    userId: string,
    action: string
  ): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true }
    });

    if (!user) return false;

    // Super admin has all permissions
    if (user.role === 'SUPER_ADMIN') return true;

    // Admin has most permissions
    if (user.role === 'ADMIN') {
      if (action === 'DELETE') return false; // Only super admin can delete
      return true;
    }

    // Check if user is election admin
    const election = await prisma.election.findFirst({
      where: {
        id: electionId,
        OR: [
          { createdById: userId },
          { admins: { some: { id: userId } } }
        ]
      }
    });

    return !!election;
  }
}

// Export singleton instance
export const electionController = new ElectionController();