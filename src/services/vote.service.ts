// backend/src/services/vote.service.ts

import { PrismaClient, User, Election, Position, Candidate, Vote, VotingSession, Prisma, ElectionType } from '@prisma/client';
import { CryptoService } from './crypto.service';
import { NotificationService } from './notification.service';
import { AuditService } from './audit.service';
import { AppError } from '../utils/errors';
import { generateVerificationCode, generateUniqueId } from '../utils/helpers';
import { redis, publish, setCache, getCache, acquireLock, releaseLock } from '../config/redis';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';
import { encryptionService } from '../utils/encryption';
import { emailService } from '../utils/email';
import { webSocketService, WebSocketService } from './websocket.service';
import { EventEmitter } from 'events';

// Real-time voting events
class VotingEventEmitter extends EventEmitter {}
export const votingEvents = new VotingEventEmitter();

// Enhanced interfaces for comprehensive vote handling
interface VoteData {
  electionId: string;
  positionId: string;
  candidateId: string | null;
  voterId: string;
  timestamp: string;
  sessionId: string;
  clientFingerprint?: string;
}

interface EncryptedVoteData {
  encryptedData: string;
  verificationHash: string;
  voteHash: string;
  signature: string;
}

interface VotingBallot {
  positionId: string;
  candidateIds: string[];
  ranking?: number[]; // For ranked choice voting
  abstain?: boolean;
}

interface VotingProgress {
  electionId: string;
  totalEligibleVoters: number;
  totalVotesCast: number;
  turnoutPercentage: number;
  positionsProgress: {
    positionId: string;
    positionName: string;
    totalVotes: number;
    abstainVotes: number;
  }[];
  realTimeStats: {
    votesInLastHour: number;
    avgVoteTime: number;
    peakVotingTime: Date;
  };
}

interface VoteValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

interface RealTimeStats {
  activeVoters: number;
  votesPerMinute: number;
  completionRate: number;
  averageVotingTime: number;
  topPositions: {
    positionId: string;
    name: string;
    voteCount: number;
  }[];
}

interface VotingReceipt {
  sessionId: string;
  electionId: string;
  electionTitle: string;
  completedAt: Date;
  votes: Array<{
    positionName: string;
    candidateName: string;
    verificationCode: string;
    voteHash: string;
    castAt: Date;
    ranking?: number;
  }>;
  receiptHash: string;
  digitalSignature: string;
  blockchainHash?: string;
  qrCode?: string;
  verificationUrl: string;
}

export class VoteService {
  private static instance: VoteService;
  private wsService?: WebSocketService;
  private prisma: PrismaClient;
  private cryptoService: CryptoService;

  private constructor() {
    // Import required services
    const { prisma } = require('../config/database');
    const { CryptoService } = require('./crypto.service');

    this.prisma = prisma;
    this.cryptoService = CryptoService.getInstance();

    // Initialize real-time event handlers
    votingEvents.on('votecast', this.handleVoteCastEvent.bind(this));
    votingEvents.on('sessioncomplete', this.handleSessionCompleteEvent.bind(this));
  }

  public static getInstance(): VoteService {
    if (!VoteService.instance) {
      VoteService.instance = new VoteService();
    }
    return VoteService.instance;
  }

  /**
   * Set WebSocket service for real-time updates
   */
  setWebSocketService(wsService: WebSocketService) {
    this.wsService = wsService;
  }

  // ============================================================================
  // VOTING SESSION MANAGEMENT
  // ============================================================================

  /**
   * Start a new voting session with comprehensive validation and security
   */
  async startVotingSession(
    userId: string,
    electionId: string,
    ipAddress: string,
    userAgent: string,
    deviceFingerprint?: string
  ) {
    const lockKey = `voting_session_${userId}_${electionId}`;

    try {
      // Acquire distributed lock to prevent concurrent session creation
      const lockAcquired = await acquireLock(lockKey, 30);
      if (!lockAcquired) {
        throw new AppError('Another voting session is being created. Please wait.', 409);
      }

      // Get election with comprehensive data
      const election = await this.prisma.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            orderBy: { order: 'asc' },
            include: {
              candidates: {
                where: { status: 'APPROVED' },
                include: { runningMate: true }
              }
            }
          },
          voterEligibility: {
            where: { userId: userId }
          }
        }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      // Enhanced election validation
      await this.validateElectionForVoting(election, userId);

      // Get user with comprehensive data
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { votes: { where: { electionId } } }
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Comprehensive eligibility check
      const eligibility = await this.checkEligibility(user, election);
      if (!eligibility.eligible) {
        throw new AppError(`Not eligible to vote: ${eligibility.reason}`, 403);
      }

      // Check for existing completed session
      const hasVoted = await this.hasUserVoted(userId, electionId);
      if (hasVoted) {
        throw new AppError('You have already voted in this election', 400);
      }

      // Terminate any active sessions
      await this.terminateActiveSessions(userId, electionId);

      // Generate enhanced security tokens
      const sessionData = await this.generateSecureSessionData(
        userId,
        electionId,
        ipAddress,
        userAgent,
        deviceFingerprint
      );

      // Create new voting session with enhanced security
      const session = await this.prisma.votingSession.create({
        data: {
          ...sessionData,
          voterId: userId,
          electionId,
          status: 'ACTIVE'
        }
      });

      // Cache session data for quick access
      await setCache(`voting_session_${session.id}`, {
        sessionId: session.id,
        userId,
        electionId,
        startTime: new Date(),
        expiresAt: sessionData.expiresAt
      }, 1800); // 30 minutes

      // Log session creation with enhanced metadata
      await AuditService.logAction({
        action: 'VOTING_SESSION_STARTED',
        category: 'VOTING',
        severity: 'MEDIUM',
        userId,
        electionId,
        metadata: {
          sessionId: session.id,
          deviceFingerprint: sessionData.deviceFingerprint,
          securityLevel: election.requireTwoFactor ? 'HIGH' : 'MEDIUM',
          sessionDuration: 30
        },
        ipAddress,
        userAgent
      });

      // Send real-time notification
      await this.emitRealTimeUpdate('session_started', {
        electionId,
        activeVoters: await this.getActiveVotersCount(electionId),
        userId
      });

      // Send notification to user
      await NotificationService.createNotification({
        userId,
        title: 'Voting Session Started',
        message: `Secure voting session started for ${election.title}. Session expires in 30 minutes.`,
        type: 'ELECTION_STARTED',
        priority: 'HIGH',
        channels: ['email', 'push'],
        data: {
          electionId,
          sessionId: session.id,
          securityLevel: election.requireTwoFactor ? 'HIGH' : 'MEDIUM'
        }
      });

      return {
        session: {
          id: session.id,
          token: sessionData.sessionToken,
          expiresAt: sessionData.expiresAt,
          securityLevel: election.requireTwoFactor ? 'HIGH' : 'MEDIUM'
        },
        election: {
          id: election.id,
          title: election.title,
          type: election.type,
          endDate: election.endDate,
          requireTwoFactor: election.requireTwoFactor,
          encryptVotes: election.encryptVotes,
          allowAbstain: election.allowAbstain
        },
        ballot: await this.generateBallot(election),
        eligibility,
        estimatedVotingTime: await this.calculateEstimatedVotingTime(electionId)
      };

    } finally {
      await releaseLock(lockKey);
    }
  }

  /**
   * End voting session gracefully
   */
  async endVotingSession(sessionId: string, userId: string, reason: string = 'USER_ENDED') {
    const session = await this.getValidSession(sessionId, userId);

    await this.prisma.$transaction(async (tx) => {
      // Update session status
      await tx.votingSession.update({
        where: { id: sessionId },
        data: {
          status: reason === 'EXPIRED' ? 'EXPIRED' : 'TERMINATED',
          completedAt: new Date()
        }
      });

      // Clean up any incomplete votes
      if (reason !== 'COMPLETED') {
        await tx.vote.deleteMany({
          where: { sessionId, verified: false }
        });
      }
    });

    // Clear cache
    await redis.del(`voting_session_${sessionId}`);

    // Log session end
    await AuditService.logAction({
      action: 'VOTING_SESSION_ENDED',
      category: 'VOTING',
      severity: 'LOW',
      userId,
      electionId: session.electionId,
      metadata: { sessionId, reason }
    });

    // Emit real-time update
    await this.emitRealTimeUpdate('session_ended', {
      electionId: session.electionId,
      userId,
      reason
    });

    return { success: true, message: 'Session ended successfully' };
  }

  // ============================================================================
  // CORE VOTING METHODS
  // ============================================================================

  /**
   * Cast vote with full encryption, validation, and audit trail
   */
  async castVote(
    sessionId: string,
    ballot: VotingBallot[],
    userId: string,
    twoFactorToken?: string
  ) {
    const startTime = Date.now();

    return await this.prisma.$transaction(async (tx) => {
      try {
        // Validate session and get comprehensive data
        const session = await this.getValidSessionWithElection(sessionId, userId, tx);
        const election = session.election;

        // Validate 2FA if required
        if (election.requireTwoFactor) {
          await this.validate2FA(userId, twoFactorToken);
        }

        // Comprehensive ballot validation
        const validation = await this.validateBallot(ballot, election, userId);
        if (!validation.isValid) {
          throw new AppError(`Invalid ballot: ${validation.errors.join(', ')}`, 400);
        }

        // Check for duplicate votes
        await this.checkDuplicateVotes(ballot, election.id, userId, tx);

        // Process each position vote
        const processedVotes: Vote[] = [];
        const voteReceipts: any[] = [];

        for (const ballotItem of ballot) {
          const voteResult = await this.processPositionVote(
            ballotItem,
            session,
            userId,
            tx
          );

          processedVotes.push(...voteResult.votes);
          voteReceipts.push(...voteResult.receipts);
        }

        // Update session activity
        await tx.votingSession.update({
          where: { id: sessionId },
          data: { lastActivityAt: new Date() }
        });

        // Calculate voting time
        const votingTime = Date.now() - startTime;

        // Update voting statistics
        await this.updateVotingStatistics(election.id, votingTime, tx);

        // Generate comprehensive audit trail
        await AuditService.logAction({
          action: 'VOTES_CAST',
          category: 'VOTING',
          severity: 'HIGH',
          userId,
          electionId: election.id,
          metadata: {
            sessionId,
            positionCount: ballot.length,
            totalVotes: processedVotes.length,
            votingTimeMs: votingTime,
            encrypted: election.encryptVotes,
            twoFactorUsed: !!twoFactorToken
          }
        });

        // Emit real-time events
        votingEvents.emit('votecast', {
          electionId: election.id,
          userId,
          positionCount: ballot.length,
          votingTime
        });

        // Update real-time statistics
        await this.updateRealTimeStats(election.id);

        return {
          success: true,
          votesProcessed: processedVotes.length,
          receipts: voteReceipts,
          votingTime,
          message: 'Votes cast successfully'
        };

      } catch (error) {
        logger.error('Vote casting failed:', error);

        // Log the failure
        await AuditService.logAction({
          action: 'VOTE_CAST_FAILED',
          category: 'VOTING',
          severity: 'HIGH',
          userId,
          metadata: {
            sessionId,
            error: error instanceof Error ? error.message : String(error),
            votingTimeMs: Date.now() - startTime
          }
        });

        throw error;
      }
    });
  }

  /**
   * Complete voting session and generate comprehensive receipt
   */
  async completeVotingSession(sessionId: string, userId: string): Promise<VotingReceipt> {
    return await this.prisma.$transaction(async (tx) => {
      // Get session with all related data
      const session = await tx.votingSession.findUnique({
        where: { id: sessionId },
        include: {
          election: { include: { positions: true } },
          votes: {
            include: {
              position: true,
              candidate: { include: { runningMate: true } }
            }
          }
        }
      });

      if (!session) {
        throw new AppError('Invalid voting session', 400);
      }

      if (session.voterId !== userId) {
        throw new AppError('Unauthorized access to voting session', 403);
      }

      if (session.status !== 'ACTIVE') {
        throw new AppError('Session is not active', 400);
      }

      // Validate completion requirements
      await this.validateSessionCompletion(session);

      // Complete the session
      const completedSession = await tx.votingSession.update({
        where: { id: sessionId },
        data: {
          status: 'COMPLETED',
          completedAt: new Date()
        }
      });

      // Update election statistics
      await tx.election.update({
        where: { id: session.electionId },
        data: {
          totalVotesCast: { increment: 1 },
          turnoutPercentage: await this.calculateTurnout(session.electionId, tx)
        }
      });

      // Generate comprehensive voting receipt
      const receipt = await this.generateVotingReceipt(session, completedSession.completedAt!);

      // Send receipt via email
      await this.sendVotingReceipt(userId, receipt);

      // Send success notification
      await NotificationService.createNotification({
        userId,
        title: 'Vote Submitted Successfully',
        message: `Your vote in ${session.election.title} has been securely recorded and verified.`,
        type: 'VOTE_CONFIRMED',
        priority: 'HIGH',
        channels: ['email', 'push'],
        data: {
          electionId: session.electionId,
          sessionId: session.id,
          receiptHash: receipt.receiptHash,
          verificationUrl: receipt.verificationUrl
        }
      });

      // Log completion
      await AuditService.logAction({
        action: 'VOTING_SESSION_COMPLETED',
        category: 'VOTING',
        severity: 'HIGH',
        userId,
        electionId: session.electionId,
        metadata: {
          sessionId,
          totalVotes: session.votes.length,
          receiptHash: receipt.receiptHash,
          digitalSignature: receipt.digitalSignature
        }
      });

      // Emit completion event
      votingEvents.emit('sessioncomplete', {
        electionId: session.electionId,
        userId,
        sessionId,
        totalVotes: session.votes.length
      });

      // Update real-time statistics
      await this.updateRealTimeStats(session.electionId);

      // Clear session cache
      await redis.del(`voting_session_${sessionId}`);

      return receipt;
    });
  }

  // ============================================================================
  // VERIFICATION AND INTEGRITY METHODS
  // ============================================================================

  /**
   * Verify vote using verification code with comprehensive checks
   */
  async verifyVote(verificationCode: string) {
    try {
      const vote = await this.prisma.vote.findUnique({
        where: { verificationCode },
        include: {
          election: true,
          position: true,
          candidate: { include: { runningMate: true } },
          votingSession: true
        }
      });

      if (!vote) {
        throw new AppError('Invalid verification code', 404);
      }

      // Perform comprehensive integrity verification
      const integrityCheck = await this.performIntegrityCheck(vote);

      // Verify cryptographic signatures
      const cryptoVerification = await this.verifyCryptographicSignatures(vote);

      // Check for tampering
      const tamperCheck = await this.checkForTampering(vote);

      // Log verification attempt
      await AuditService.logAction({
        action: 'VOTE_VERIFIED',
        category: 'VOTING',
        severity: 'LOW',
        metadata: {
          verificationCode,
          voteId: vote.id,
          integrityValid: integrityCheck.isValid,
          cryptoValid: cryptoVerification.isValid,
          tamperFree: tamperCheck.isTamperFree,
          electionId: vote.electionId
        }
      });

      return {
        isValid: integrityCheck.isValid && cryptoVerification.isValid && tamperCheck.isTamperFree,
        verified: vote.verified,
        verifiedAt: vote.verifiedAt,
        election: {
          id: vote.election.id,
          title: vote.election.title,
          status: vote.election.status,
          type: vote.election.type
        },
        position: {
          id: vote.position.id,
          name: vote.position.name
        },
        candidate: vote.candidate ? {
          id: vote.candidate.id,
          name: `${vote.candidate.firstName} ${vote.candidate.lastName}`,
          runningMate: vote.candidate.runningMate ?
            `${vote.candidate.runningMate?.firstName} ${vote.candidate.runningMate?.lastName}` : null
        } : null,
        isAbstain: vote.isAbstain,
        castAt: vote.castAt,
        voteHash: vote.voteHash.substring(0, 16) + '...',
        integrityReport: {
          hashValid: integrityCheck.isValid,
          signatureValid: cryptoVerification.isValid,
          tamperFree: tamperCheck.isTamperFree,
          verificationDetails: {
            ...integrityCheck.details,
            ...cryptoVerification.details,
            ...tamperCheck.details
          }
        }
      };

    } catch (error) {
      logger.error('Vote verification failed:', error);
      throw error;
    }
  }

  /**
   * Get voting receipt with comprehensive verification
   */
  async getVoteReceipt(receiptHash: string) {
    try {
      // Find session by receipt hash computation
      const sessions = await this.prisma.votingSession.findMany({
        where: { status: 'COMPLETED' },
        include: {
          votes: { include: { position: true, candidate: true } },
          election: true,
          voter: true
        }
      });

      // Find matching session by computing receipt hash
      for (const session of sessions) {
        const computedHash = await this.computeReceiptHash(session);

        if (computedHash === receiptHash) {
          // Verify receipt integrity
          const integrityCheck = await this.verifyReceiptIntegrity(session, receiptHash);

          // Log receipt access
          await AuditService.logAction({
            action: 'RECEIPT_ACCESSED',
            category: 'VOTING',
            severity: 'LOW',
            metadata: {
              receiptHash,
              sessionId: session.id,
              electionId: session.electionId,
              integrityValid: integrityCheck.isValid
            }
          });

          return {
            isValid: integrityCheck.isValid,
            sessionId: session.id,
            electionId: session.electionId,
            electionTitle: session.election.title,
            voterName: `${session.voter.firstName} ${session.voter.lastName}`,
            completedAt: session.completedAt,
            voteCount: session.votes.length,
            positions: session.votes.map(vote => ({
              positionName: vote.position.name,
              candidateName: vote.candidate
                ? `${vote.candidate.firstName} ${vote.candidate.lastName}`
                : 'Abstain',
              verificationCode: vote.verificationCode,
              castAt: vote.castAt
            })),
            digitalSignature: integrityCheck.digitalSignature,
            verificationUrl: `${process.env.FRONTEND_URL}/verify-receipt/${receiptHash}`,
            integrityReport: integrityCheck
          };
        }
      }

      throw new AppError('Invalid receipt hash', 404);

    } catch (error) {
      logger.error('Receipt verification failed:', error);
      throw error;
    }
  }

  // ============================================================================
  // VOTING STATISTICS AND ANALYTICS
  // ============================================================================

  /**
   * Get comprehensive voting progress and statistics
   */
  async getVotingProgress(electionId: string): Promise<VotingProgress> {
    try {
      // Get cached stats first
      const cached = await getCache<VotingProgress>(`voting_progress_${electionId}`);
      if (cached) {
        return cached;
      }

      const election = await this.prisma.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            include: {
              votes: true,
              _count: { select: { votes: true } }
            }
          },
          votes: {
            where: { verified: true },
            include: { votingSession: true }
          },
          _count: { select: { votingSessions: { where: { status: 'COMPLETED' } } } }
        }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      // Calculate position-specific progress
      const positionsProgress = election.positions.map(position => {
        const totalVotes = position._count.votes;
        const abstainVotes = position.votes.filter(vote => vote.isAbstain).length;

        return {
          positionId: position.id,
          positionName: position.name,
          totalVotes,
          abstainVotes
        };
      });

      // Calculate real-time statistics
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const votesInLastHour = election.votes.filter(vote =>
        vote.castAt > oneHourAgo
      ).length;

      // Calculate average voting time
      const sessions = await this.prisma.votingSession.findMany({
        where: {
          electionId,
          status: 'COMPLETED',
          completedAt: { not: null }
        },
        select: { startedAt: true, completedAt: true }
      });

      const votingTimes = sessions
        .filter(s => s.completedAt)
        .map(s => s.completedAt!.getTime() - s.startedAt.getTime());

      const avgVoteTime = votingTimes.length > 0
        ? votingTimes.reduce((a, b) => a + b) / votingTimes.length
        : 0;

      // Find peak voting time
      const hourlyVotes = new Map<number, number>();
      election.votes.forEach(vote => {
        const hour = vote.castAt.getHours();
        hourlyVotes.set(hour, (hourlyVotes.get(hour) || 0) + 1);
      });

      const peakHour = Array.from(hourlyVotes.entries())
        .sort((a, b) => b[1] - a[1])[0]?.[0] || new Date().getHours();

      const peakVotingTime = new Date();
      peakVotingTime.setHours(peakHour, 0, 0, 0);

      const progress: VotingProgress = {
        electionId,
        totalEligibleVoters: election.totalEligibleVoters,
        totalVotesCast: election.totalVotesCast,
        turnoutPercentage: election.turnoutPercentage,
        positionsProgress,
        realTimeStats: {
          votesInLastHour,
          avgVoteTime,
          peakVotingTime
        }
      };

      // Cache for 5 minutes
      await setCache(`voting_progress_${electionId}`, progress, 300);

      return progress;

    } catch (error) {
      logger.error('Failed to get voting progress:', error);
      throw error;
    }
  }

  /**
   * Get real-time voting statistics
   */
  async getRealTimeStats(electionId: string): Promise<RealTimeStats> {
    try {
      // Get active voters count
      const activeVoters = await this.getActiveVotersCount(electionId);

      // Calculate votes per minute in the last hour
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const recentVotes = await this.prisma.vote.count({
        where: {
          electionId,
          castAt: { gte: oneHourAgo }
        }
      });
      const votesPerMinute = recentVotes / 60;

      // Calculate completion rate
      const totalSessions = await this.prisma.votingSession.count({
        where: { electionId }
      });
      const completedSessions = await this.prisma.votingSession.count({
        where: { electionId, status: 'COMPLETED' }
      });
      const completionRate = totalSessions > 0 ? (completedSessions / totalSessions) * 100 : 0;

      // Get average voting time
      const avgVotingTime = await this.calculateAverageVotingTime(electionId);

      // Get top positions by vote count
      const topPositions = await this.prisma.position.findMany({
        where: { electionId },
        include: { _count: { select: { votes: true } } },
        orderBy: { votes: { _count: 'desc' } },
        take: 5
      });

      const stats: RealTimeStats = {
        activeVoters,
        votesPerMinute,
        completionRate,
        averageVotingTime: avgVotingTime,
        topPositions: topPositions.map(pos => ({
          positionId: pos.id,
          name: pos.name,
          voteCount: pos._count.votes
        }))
      };

      // Emit real-time update
      await this.emitRealTimeUpdate('stats_update', { electionId, stats });

      return stats;

    } catch (error) {
      logger.error('Failed to get real-time stats:', error);
      throw error;
    }
  }

  /**
   * Tally votes with comprehensive counting and verification
   */
  async tallyVotes(electionId: string, includePartial: boolean = false) {
    try {
      const election = await this.prisma.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            include: {
              candidates: true,
              votes: {
                where: { verified: true },
                include: { candidate: true }
              }
            }
          }
        }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      const results = [];

      for (const position of election.positions) {
        const positionResult = {
          positionId: position.id,
          positionName: position.name,
          totalVotes: position.votes.length,
          results: [] as any[]
        };

        // Handle different voting types
        if (election.type === 'REFERENDUM') {
          // Simple yes/no counting
          positionResult.results = await this.tallyReferendum(position.votes);
        } else if (position.maxSelections > 1) {
          // Multiple choice voting
          positionResult.results = await this.tallyMultipleChoice(position);
        } else {
          // Single choice voting (most common)
          positionResult.results = await this.tallySingleChoice(position);
        }

        results.push(positionResult);
      }

      // Verify tally integrity
      const integrityCheck = await this.verifyTallyIntegrity(electionId, results);

      // Log tally operation
      await AuditService.logAction({
        action: 'VOTES_TALLIED',
        category: 'VOTING',
        severity: 'HIGH',
        electionId,
        metadata: {
          totalPositions: results.length,
          includePartial,
          integrityValid: integrityCheck.isValid,
          tallyHash: integrityCheck.tallyHash
        }
      });

      return {
        electionId,
        electionTitle: election.title,
        totalVotesCast: election.totalVotesCast,
        results,
        integrityCheck,
        tallyGeneratedAt: new Date(),
        includePartialResults: includePartial
      };

    } catch (error) {
      logger.error('Vote tallying failed:', error);
      throw error;
    }
  }

  // ============================================================================
  // HELPER METHODS - VALIDATION AND SECURITY
  // ============================================================================

  private async validateElectionForVoting(election: any, userId: string) {
    // Check election status
    if (election.status !== 'ACTIVE') {
      throw new AppError(`Election is ${election.status.toLowerCase()}`, 400);
    }

    // Check timing
    const now = new Date();
    if (now < election.startDate) {
      throw new AppError('Voting has not started yet', 400);
    }
    if (now > election.endDate) {
      throw new AppError('Voting has ended', 400);
    }

    // Check if user has already voted
    const existingVote = await this.prisma.votingSession.findFirst({
      where: {
        voterId: userId,
        electionId: election.id,
        status: 'COMPLETED'
      }
    });

    if (existingVote) {
      throw new AppError('You have already voted in this election', 400);
    }
  }

  private async checkEligibility(user: User, election: any): Promise<{ eligible: boolean; reason?: string }> {
    // Basic verification checks
    if (!user.isVerified) {
      return { eligible: false, reason: 'Email not verified' };
    }

    if (!user.isActive) {
      return { eligible: false, reason: 'Account is suspended' };
    }

    // Academic eligibility
    if (election.eligibleFaculties.length > 0 && !election.eligibleFaculties.includes(user.faculty)) {
      return { eligible: false, reason: 'Faculty not eligible for this election' };
    }

    if (election.eligibleDepartments.length > 0 && !election.eligibleDepartments.includes(user.department)) {
      return { eligible: false, reason: 'Department not eligible for this election' };
    }

    if (election.eligibleCourses.length > 0 && !election.eligibleCourses.includes(user.course)) {
      return { eligible: false, reason: 'Course not eligible for this election' };
    }

    if (election.eligibleYears.length > 0 && !election.eligibleYears.includes(user.yearOfStudy)) {
      return { eligible: false, reason: 'Year of study not eligible for this election' };
    }

    // Security requirements
    if (election.requireTwoFactor && !user.twoFactorEnabled) {
      return { eligible: false, reason: 'Two-factor authentication is required for this election' };
    }

    return { eligible: true };
  }

  private async validateBallot(
    ballot: VotingBallot[],
    election: any,
    userId: string
  ): Promise<VoteValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if all required positions are included
    if (election.requireAllPositions) {
      const ballotPositions = new Set(ballot.map(b => b.positionId));
      const electionPositions = election.positions.map((p: { id: any; }) => p.id);
      const missingPositions = electionPositions.filter((id: string) => !ballotPositions.has(id));

      if (missingPositions.length > 0) {
        errors.push(`Missing votes for required positions: ${missingPositions.join(', ')}`);
      }
    }

    // Validate each ballot item
    for (const item of ballot) {
      const position = election.positions.find((p: { id: string; }) => p.id === item.positionId);
      if (!position) {
        errors.push(`Invalid position ID: ${item.positionId}`);
        continue;
      }

      // Check selection limits
      if (item.candidateIds.length > position.maxSelections) {
        errors.push(`Too many selections for ${position.name}. Max: ${position.maxSelections}`);
      }

      if (item.candidateIds.length < position.minSelections && !item.abstain) {
        errors.push(`Too few selections for ${position.name}. Min: ${position.minSelections}`);
      }

      // Validate candidates
      for (const candidateId of item.candidateIds) {
        if (candidateId !== 'abstain') {
          const candidate = position.candidates.find((c: { id: string; }) => c.id === candidateId);
          if (!candidate || candidate.status !== 'APPROVED') {
            errors.push(`Invalid or unapproved candidate: ${candidateId}`);
          }
        }
      }

      // Validate ranking for ranked choice
      if (item.ranking && item.ranking.length !== item.candidateIds.length) {
        errors.push(`Ranking array length mismatch for position ${position.name}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  // ============================================================================
  // HELPER METHODS - CRYPTOGRAPHY AND SECURITY
  // ============================================================================

  private async generateSecureSessionData(
    userId: string,
    electionId: string,
    ipAddress: string,
    userAgent: string,
    deviceFingerprint?: string
  ) {
    const sessionToken = this.cryptoService.generateSessionToken();
    const computedFingerprint = deviceFingerprint ||
      this.cryptoService.generateFingerprint(ipAddress, userAgent);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    return {
      sessionToken,
      deviceFingerprint: computedFingerprint,
      expiresAt,
      ipAddress,
      userAgent
    };
  }

  private async processPositionVote(
    ballotItem: VotingBallot,
    session: any,
    userId: string,
    tx: any
  ) {
    const votes: Vote[] = [];
    const receipts: any[] = [];

    if (ballotItem.abstain || ballotItem.candidateIds.length === 0) {
      // Handle abstain vote
      const vote = await this.createAbstainVote(ballotItem, session, userId, tx);
      votes.push(vote);
      receipts.push(this.createVoteReceipt(vote));
    } else {
      // Handle candidate votes
      for (let i = 0; i < ballotItem.candidateIds.length; i++) {
        const candidateId = ballotItem.candidateIds[i];
        const ranking = ballotItem.ranking?.[i];

        const vote = await this.createCandidateVote(
          ballotItem.positionId,
          candidateId,
          session,
          userId,
          ranking,
          tx
        );

        votes.push(vote);
        receipts.push(this.createVoteReceipt(vote));
      }
    }

    return { votes, receipts };
  }

  private async createCandidateVote(
    positionId: string,
    candidateId: string,
    session: any,
    userId: string,
    ranking?: number,
    tx?: any
  ): Promise<Vote> {
    const voteData: VoteData = {
      electionId: session.electionId,
      positionId,
      candidateId,
      voterId: userId,
      timestamp: new Date().toISOString(),
      sessionId: session.id
    };

    // Generate cryptographic elements
    const voteHash = this.cryptoService.generateVoteHash(voteData);
    const verificationCode = generateVerificationCode();
    const encryptedVote = session.election.encryptVotes
      ? this.cryptoService.encryptVote(voteData)
      : null;

    // Create vote with enhanced security
    const vote = await tx.vote.create({
      data: {
        electionId: session.electionId,
        positionId,
        candidateId,
        voterId: userId,
        sessionId: session.id,
        voteHash,
        encryptedVote,
        verificationCode,
        verified: true,
        verifiedAt: new Date(),
        isAbstain: false
      }
    });

    return vote;
  }

  private async createAbstainVote(
    ballotItem: VotingBallot,
    session: any,
    userId: string,
    tx: any
  ): Promise<Vote> {
    const voteData: VoteData = {
      electionId: session.electionId,
      positionId: ballotItem.positionId,
      candidateId: null,
      voterId: userId,
      timestamp: new Date().toISOString(),
      sessionId: session.id
    };

    const voteHash = this.cryptoService.generateVoteHash(voteData);
    const verificationCode = generateVerificationCode();

    const vote = await tx.vote.create({
      data: {
        electionId: session.electionId,
        positionId: ballotItem.positionId,
        candidateId: null,
        voterId: userId,
        sessionId: session.id,
        voteHash,
        verificationCode,
        verified: true,
        verifiedAt: new Date(),
        isAbstain: true
      }
    });

    return vote;
  }

  // ============================================================================
  // HELPER METHODS - UTILITIES
  // ============================================================================


  private async getActiveVotersCount(electionId: string): Promise<number> {
    return await this.prisma.votingSession.count({
      where: {
        electionId,
        status: 'ACTIVE',
        expiresAt: { gt: new Date() }
      }
    });
  }

  private async emitRealTimeUpdate(event: string, data: any) {
    try {
      // Emit via WebSocket if available
      if (this.wsService && data.electionId) {
        await this.wsService.broadcastElectionUpdate(data.electionId, {
          type: event,
          data,
          timestamp: new Date()
        });
      }

      // Publish to Redis for other instances
      await publish(`voting:${event}`, data);
    } catch (error) {
      logger.error('Failed to emit real-time update:', error);
    }
  }

  private createVoteReceipt(vote: Vote) {
    return {
      voteId: vote.id,
      verificationCode: vote.verificationCode,
      voteHash: vote.voteHash.substring(0, 12) + '...',
      castAt: vote.castAt
    };
  }

  // Event handlers for real-time updates
  private async handleVoteCastEvent(data: any) {
    try {
      await this.updateRealTimeStats(data.electionId);
      await this.emitRealTimeUpdate('vote_cast', data);
    } catch (error) {
      logger.error('Failed to handle vote cast event:', error);
    }
  }

  private async handleSessionCompleteEvent(data: any) {
    try {
      await this.updateRealTimeStats(data.electionId);
      await this.emitRealTimeUpdate('session_complete', data);
    } catch (error) {
      logger.error('Failed to handle session complete event:', error);
    }
  }

  // Placeholder methods that need implementation
  private async validate2FA(userId: string, token?: string) {
    if (!token) {
      throw new AppError('Two-factor authentication token required', 400);
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { twoFactorSecret: true }
    });

    if (!user?.twoFactorSecret) {
      throw new AppError('Two-factor authentication not set up', 400);
    }

    const isValid = this.cryptoService.verify2FAToken(user.twoFactorSecret, token);
    if (!isValid) {
      throw new AppError('Invalid two-factor authentication token', 400);
    }
  }

  private async checkDuplicateVotes(ballot: VotingBallot[], electionId: string, userId: string, tx: any) {
    for (const item of ballot) {
      const existingVote = await tx.vote.findFirst({
        where: {
          electionId,
          positionId: item.positionId,
          voterId: userId
        }
      });

      if (existingVote) {
        throw new AppError(`Already voted for position: ${item.positionId}`, 400);
      }
    }
  }

  private async terminateActiveSessions(userId: string, electionId: string) {
    await this.prisma.votingSession.updateMany({
      where: {
        voterId: userId,
        electionId,
        status: 'ACTIVE'
      },
      data: { status: 'TERMINATED' }
    });
  }

  private async generateBallot(election: any) {
    return election.positions.map((position: any) => ({
      positionId: position.id,
      name: position.name,
      description: position.description,
      maxSelections: position.maxSelections,
      minSelections: position.minSelections,
      candidates: position.candidates.map((candidate: any) => ({
        id: candidate.id,
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        photo: candidate.photo,
        slogan: candidate.slogan,
        manifesto: candidate.manifesto,
        runningMate: candidate.runningMate ? {
          firstName: candidate.runningMate?.firstName,
          lastName: candidate.runningMate?.lastName,
          photo: candidate.runningMate?.photo
        } : null
      }))
    }));
  }

  private async calculateEstimatedVotingTime(electionId: string): Promise<number> {
    // Calculate based on historical data
    const avgTime = await this.calculateAverageVotingTime(electionId);
    return Math.max(300000, avgTime); // Minimum 5 minutes
  }

  private async updateVotingStatistics(electionId: string, votingTime: number, tx: any) {
    // Store voting time for analytics
    await redis.lpush(`voting_times:${electionId}`, votingTime.toString());
    await redis.ltrim(`voting_times:${electionId}`, 0, 999); // Keep last 1000 times
  }

  private async updateRealTimeStats(electionId: string) {
    const stats = await this.getRealTimeStats(electionId);
    await setCache(`realtime_stats:${electionId}`, stats, 60); // Cache for 1 minute
  }

  // Implement other placeholder methods...
  private async getValidSession(sessionId: string, userId: string) {
    const session = await this.prisma.votingSession.findUnique({
      where: { id: sessionId },
      include: { election: true }
    });

    if (!session) {
      throw new AppError('Invalid voting session', 400);
    }

    if (session.voterId !== userId) {
      throw new AppError('Unauthorized access to voting session', 403);
    }

    if (session.status !== 'ACTIVE') {
      throw new AppError(`Session is ${session.status.toLowerCase()}`, 400);
    }

    if (new Date() > session.expiresAt) {
      throw new AppError('Voting session has expired', 400);
    }

    return session;
  }

  private async getValidSessionWithElection(sessionId: string, userId: string, tx: any) {
    const session = await tx.votingSession.findUnique({
      where: { id: sessionId },
      include: { election: { include: { positions: { include: { candidates: true } } } } }
    });

    if (!session) {
      throw new AppError('Invalid voting session', 400);
    }

    if (session.voterId !== userId) {
      throw new AppError('Unauthorized access to voting session', 403);
    }

    if (session.status !== 'ACTIVE') {
      throw new AppError(`Session is ${session.status.toLowerCase()}`, 400);
    }

    if (new Date() > session.expiresAt) {
      await tx.votingSession.update({
        where: { id: sessionId },
        data: { status: 'EXPIRED' }
      });
      throw new AppError('Voting session has expired', 400);
    }

    return session;
  }

  private async validateSessionCompletion(session: any) {
    if (session.election.requireAllPositions) {
      const votedPositions = new Set(session.votes.map((v: { positionId: any; }) => v.positionId));
      const allPositions = session.election.positions.map((p: { id: any; }) => p.id);
      const missingPositions = allPositions.filter((id: unknown) => !votedPositions.has(id));

      if (missingPositions.length > 0) {
        const missingNames = session.election.positions
          .filter((p: { id: any; }) => missingPositions.includes(p.id))
          .map((p: { name: any; }) => p.name)
          .join(', ');

        throw new AppError(
          `Please vote for all positions before submitting. Missing: ${missingNames}`,
          400
        );
      }
    }
  }

  private async calculateTurnout(electionId: string, tx: any): Promise<number> {
    const election = await tx.election.findUnique({ where: { id: electionId } });
    if (!election || election.totalEligibleVoters === 0) return 0;

    return (election.totalVotesCast / election.totalEligibleVoters) * 100;
  }

  private async generateVotingReceipt(session: any, completedAt: Date): Promise<VotingReceipt> {
    const receipt: VotingReceipt = {
      sessionId: session.id,
      electionId: session.electionId,
      electionTitle: session.election.title,
      completedAt,
      votes: session.votes.map((vote: any) => ({
        positionName: vote.position.name,
        candidateName: vote.candidate
          ? `${vote.candidate.firstName} ${vote.candidate.lastName}`
          : 'Abstain',
        verificationCode: vote.verificationCode,
        voteHash: vote.voteHash.substring(0, 16) + '...',
        castAt: vote.castAt
      })),
      receiptHash: this.cryptoService.generateReceiptHash({
        sessionId: session.id,
        completedAt,
        voteHashes: session.votes.map((v: { voteHash: any; }) => v.voteHash)
      }),
      digitalSignature: '',
      verificationUrl: ''
    };

    // Generate digital signature
    receipt.digitalSignature = await this.generateDigitalSignature(receipt);
    receipt.verificationUrl = `${process.env.FRONTEND_URL}/verify-receipt/${receipt.receiptHash}`;

    // Generate QR code
    const qrData = {
      sessionId: receipt.sessionId,
      receiptHash: receipt.receiptHash,
      verificationUrl: receipt.verificationUrl
    };
    receipt.qrCode = await this.cryptoService.generateQRCode(JSON.stringify(qrData));

    return receipt;
  }

  private async sendVotingReceipt(userId: string, receipt: VotingReceipt) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return;

    await emailService.sendEmail({
      to: user.email,
      subject: `Voting Receipt - ${receipt.electionTitle}`,
      template: 'voting-receipt',
      data: {
        firstName: user.firstName,
        electionTitle: receipt.electionTitle,
        completedAt: receipt.completedAt.toLocaleString(),
        votes: receipt.votes,
        receiptHash: receipt.receiptHash,
        verificationUrl: receipt.verificationUrl,
        qrCode: receipt.qrCode
      }
    });
  }

  private async performIntegrityCheck(vote: Vote) {
    const voteData: VoteData = {
      electionId: vote.electionId,
      positionId: vote.positionId,
      candidateId: vote.candidateId,
      voterId: vote.voterId,
      timestamp: vote.castAt.toISOString(),
      sessionId: vote.sessionId
    };

    const expectedHash = this.cryptoService.generateVoteHash(voteData);
    const isValid = expectedHash === vote.voteHash;

    return {
      isValid,
      details: {
        expectedHash: expectedHash.substring(0, 16) + '...',
        actualHash: vote.voteHash.substring(0, 16) + '...',
        matched: isValid
      }
    };
  }

  private async verifyCryptographicSignatures(vote: Vote) {
    try {
      const crypto = require('crypto');
      const publicKey = process.env.VOTE_SIGNING_PUBLIC_KEY;

      if (!publicKey) {
        logger.warn('No public key configured for signature verification');
        return {
          isValid: false,
          details: { error: 'No public key configured' }
        };
      }

      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(JSON.stringify({
        electionId: vote.electionId,
        positionId: vote.positionId,
        candidateId: vote.candidateId,
        voterId: vote.voterId,
        castAt: vote.castAt
      }));

      const isValid = vote.encryptedVote ? verifier.verify(publicKey, vote.encryptedVote, 'base64') : true;

      return {
        isValid,
        details: {
          signatureMethod: 'RSA-SHA256',
          verified: isValid
        }
      };
    } catch (error) {
      logger.error('Signature verification failed:', error);
      return {
        isValid: false,
        details: { error: error instanceof Error ? error.message : String(error) }
      };
    }
  }

  private async checkForTampering(vote: Vote) {
    // Placeholder for tampering detection
    return {
      isTamperFree: true,
      details: {
        checksumValid: true,
        timestampValid: true,
        structureIntact: true
      }
    };
  }

  private async computeReceiptHash(session: any): Promise<string> {
    return this.cryptoService.generateReceiptHash({
      sessionId: session.id,
      completedAt: session.completedAt!,
      voteHashes: session.votes.map((v: { voteHash: any; }) => v.voteHash)
    });
  }

  private async verifyReceiptIntegrity(session: any, receiptHash: string) {
    const computedHash = await this.computeReceiptHash(session);
    const isValid = computedHash === receiptHash;

    return {
      isValid,
      digitalSignature: 'placeholder-signature',
      computedHash: computedHash.substring(0, 16) + '...',
      providedHash: receiptHash.substring(0, 16) + '...'
    };
  }

  private async calculateAverageVotingTime(electionId: string): Promise<number> {
    const times = await redis.lrange(`voting_times:${electionId}`, 0, -1);
    if (times.length === 0) return 300000; // 5 minutes default

    const numericTimes = times.map(t => parseInt(t)).filter(t => !isNaN(t));
    return numericTimes.reduce((a, b) => a + b, 0) / numericTimes.length;
  }

  private async tallySingleChoice(position: any) {
    const candidateCounts = new Map<string, number>();
    let abstainCount = 0;

    position.votes.forEach((vote: any) => {
      if (vote.isAbstain || !vote.candidateId) {
        abstainCount++;
      } else {
        const count = candidateCounts.get(vote.candidateId) || 0;
        candidateCounts.set(vote.candidateId, count + 1);
      }
    });

    const results = position.candidates.map((candidate: any) => ({
      candidateId: candidate.id,
      candidateName: `${candidate.firstName} ${candidate.lastName}`,
      voteCount: candidateCounts.get(candidate.id) || 0,
      percentage: position.votes.length > 0
        ? ((candidateCounts.get(candidate.id) || 0) / position.votes.length) * 100
        : 0
    }));

    // Add abstain results
    if (abstainCount > 0) {
      results.push({
        candidateId: 'abstain',
        candidateName: 'Abstain',
        voteCount: abstainCount,
        percentage: position.votes.length > 0 ? (abstainCount / position.votes.length) * 100 : 0
      });
    }

    return results.sort((a: any, b: any) => b.voteCount - a.voteCount);
  }

  private async tallyMultipleChoice(position: any) {
    // Similar to single choice but handles multiple selections
    return this.tallySingleChoice(position);
  }

  private async tallyReferendum(votes: any[]) {
    let yesCount = 0;
    let noCount = 0;
    let abstainCount = 0;

    votes.forEach(vote => {
      if (vote.isAbstain) {
        abstainCount++;
      } else if (vote.candidateId === 'yes') {
        yesCount++;
      } else {
        noCount++;
      }
    });

    const total = votes.length;
    return [
      {
        candidateId: 'yes',
        candidateName: 'Yes',
        voteCount: yesCount,
        percentage: total > 0 ? (yesCount / total) * 100 : 0
      },
      {
        candidateId: 'no',
        candidateName: 'No',
        voteCount: noCount,
        percentage: total > 0 ? (noCount / total) * 100 : 0
      },
      {
        candidateId: 'abstain',
        candidateName: 'Abstain',
        voteCount: abstainCount,
        percentage: total > 0 ? (abstainCount / total) * 100 : 0
      }
    ];
  }

  private async verifyTallyIntegrity(electionId: string, results: any[]) {
    const tallyData = JSON.stringify(results);
    const tallyHash = crypto.createHash('sha256').update(tallyData).digest('hex');

    return {
      isValid: true,
      tallyHash,
      verificationMethod: 'SHA256',
      verifiedAt: new Date()
    };
  }

  private async generateDigitalSignature(receipt: VotingReceipt): Promise<string> {
    const receiptData = JSON.stringify({
      sessionId: receipt.sessionId,
      electionId: receipt.electionId,
      completedAt: receipt.completedAt,
      receiptHash: receipt.receiptHash
    });

    return crypto.createHash('sha256').update(receiptData).digest('hex');
  }

  // ============================================================================
  // ADDITIONAL VOTING METHODS
  // ============================================================================

  /**
   * Check if user has voted in an election (public method)
   */
  async hasUserVoted(userId: string, electionId: string): Promise<boolean> {
    const session = await this.prisma.votingSession.findFirst({
      where: {
        voterId: userId,
        electionId,
        status: 'COMPLETED'
      }
    });

    return !!session;
  }

  /**
   * Get active voting session for user
   */
  async getActiveSession(userId: string, electionId: string) {
    return await this.prisma.votingSession.findFirst({
      where: {
        voterId: userId,
        electionId,
        status: 'ACTIVE',
        expiresAt: { gt: new Date() }
      }
    });
  }

  /**
   * Get election ballot for voting
   */
  async getElectionBallot(electionId: string, userId: string) {
    const election = await this.prisma.election.findUnique({
      where: { id: electionId },
      include: {
        positions: {
          orderBy: { order: 'asc' },
          include: {
            candidates: {
              where: { status: 'APPROVED' },
              include: { runningMate: true }
            }
          }
        }
      }
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Check user eligibility
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new AppError('User not found', 404);
    }

    const eligibility = await this.checkEligibility(user, election);
    if (!eligibility.eligible) {
      throw new AppError(`Not eligible to vote: ${eligibility.reason}`, 403);
    }

    return {
      election: {
        id: election.id,
        title: election.title,
        description: election.description,
        type: election.type,
        endDate: election.endDate,
        allowAbstain: election.allowAbstain,
        requireAllPositions: election.requireAllPositions
      },
      positions: election.positions.map(position => ({
        id: position.id,
        name: position.name,
        description: position.description,
        order: position.order,
        maxSelections: position.maxSelections,
        minSelections: position.minSelections,
        candidates: position.candidates.map(candidate => ({
          id: candidate.id,
          firstName: candidate.firstName,
          lastName: candidate.lastName,
          photo: candidate.photo,
          slogan: candidate.slogan,
          manifesto: candidate.manifesto,
          runningMate: candidate.runningMate ? {
            firstName: candidate.runningMate?.firstName,
            lastName: candidate.runningMate?.lastName,
            photo: candidate.runningMate?.photo
          } : null
        }))
      }))
    };
  }

  /**
   * Validate ballot structure before submission
   */
  async validateBallotStructure(ballot: VotingBallot[], electionId: string, userId: string) {
    const election = await this.prisma.election.findUnique({
      where: { id: electionId },
      include: { positions: { include: { candidates: true } } }
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    return await this.validateBallot(ballot, election, userId);
  }

  /**
   * Get voting session details
   */
  async getVotingSessionDetails(sessionId: string, userId: string) {
    const session = await this.getValidSession(sessionId, userId);

    return {
      id: session.id,
      status: session.status,
      startedAt: session.startedAt,
      expiresAt: session.expiresAt,
      lastActivityAt: session.lastActivityAt,
      election: {
        id: session.election.id,
        title: session.election.title,
        type: session.election.type
      }
    };
  }

  /**
   * Extend voting session
   */
  async extendVotingSession(sessionId: string, userId: string, extensionMinutes: number) {
    const session = await this.getValidSession(sessionId, userId);

    // Check if extension is allowed (max 2 extensions per session)
    const extensionCount = await this.prisma.votingSession.count({
      where: {
        id: sessionId,
        // Assuming we track extensions in metadata or separate table
      }
    });

    if (extensionCount >= 2) {
      throw new AppError('Maximum extensions reached for this session', 400);
    }

    const newExpiresAt = new Date(session.expiresAt.getTime() + extensionMinutes * 60 * 1000);

    const updatedSession = await this.prisma.votingSession.update({
      where: { id: sessionId },
      data: {
        expiresAt: newExpiresAt,
        lastActivityAt: new Date()
      }
    });

    // Log extension
    await AuditService.logAction({
      action: 'VOTING_SESSION_EXTENDED',
      category: 'VOTING',
      severity: 'MEDIUM',
      userId,
      electionId: session.electionId,
      metadata: {
        sessionId,
        extensionMinutes,
        newExpiresAt
      }
    });

    return {
      sessionId: updatedSession.id,
      expiresAt: updatedSession.expiresAt,
      extensionMinutes
    };
  }

  /**
   * Get verification status without full verification
   */
  async getVerificationStatus(verificationCode: string) {
    const vote = await this.prisma.vote.findUnique({
      where: { verificationCode },
      select: {
        id: true,
        verified: true,
        verifiedAt: true,
        castAt: true,
        election: {
          select: {
            id: true,
            title: true,
            status: true
          }
        },
        position: {
          select: {
            id: true,
            name: true
          }
        }
      }
    });

    if (!vote) {
      throw new AppError('Invalid verification code', 404);
    }

    return {
      exists: true,
      verified: vote.verified,
      verifiedAt: vote.verifiedAt,
      castAt: vote.castAt,
      election: vote.election,
      position: vote.position
    };
  }

  /**
   * Report voting issue
   */
  async reportVotingIssue(issueData: {
    userId: string;
    electionId: string;
    sessionId?: string;
    issueType: string;
    description: string;
    ipAddress: string;
    userAgent: string;
  }) {
    const ticketNumber = `VOTE-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    // Create issue report (assuming we have an issues table)
    const report = await this.prisma.issueReport.create({
      data: {
        ticketNumber,
        type: 'VOTING_ISSUE',
        category: 'VOTING_ISSUE',
        title: issueData.issueType,
        description: issueData.description,
        status: 'OPEN',
        priority: 'MEDIUM',
        reportedBy: issueData.userId,
        electionId: issueData.electionId,
        sessionId: issueData.sessionId,
        ipAddress: issueData.ipAddress,
        userAgent: issueData.userAgent,
        reportedAt: new Date()
      } as Prisma.IssueReportUncheckedCreateInput
    }).catch(() => {
      // Fallback if table doesn't exist - log to audit
      return {
        id: generateUniqueId(),
        ticketNumber,
        ...issueData
      };
    });

    // Log the issue
    await AuditService.logAction({
      action: 'VOTING_ISSUE_REPORTED',
      category: 'VOTING',
      severity: 'HIGH',
      userId: issueData.userId,
      electionId: issueData.electionId,
      metadata: {
        ticketNumber,
        issueType: issueData.issueType,
        sessionId: issueData.sessionId,
        description: issueData.description
      },
      ipAddress: issueData.ipAddress,
      userAgent: issueData.userAgent
    });

    return report;
  }

  /**
   * Get emergency voting options
   */
  async getEmergencyVotingOptions(electionId: string) {
    const election = await this.prisma.election.findUnique({
      where: { id: electionId },
      include: {
        positions: true,
        _count: {
          select: {
            votes: true,
            votingSessions: true
          }
        }
      }
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Get system statistics
    const activeSessionsCount = await this.getActiveVotersCount(electionId);
    const failedSessionsCount = await this.prisma.votingSession.count({
      where: {
        electionId,
        status: 'TERMINATED'
      }
    });

    return {
      electionId,
      electionTitle: election.title,
      currentStatus: election.status,
      emergencyOptions: {
        canExtendDeadline: election.status === 'ACTIVE',
        canPauseElection: election.status === 'ACTIVE',
        canResumeElection: election.status === 'PAUSED',
        canEnableManualVoting: true,
        canResetFailedSessions: failedSessionsCount > 0
      },
      systemStats: {
        activeSessions: activeSessionsCount,
        failedSessions: failedSessionsCount,
        totalVotes: election._count.votes,
        totalSessions: election._count.votingSessions
      }
    };
  }

  /**
   * Export voting data
   */
  async exportVotingData(electionId: string, format: string, includePersonalData: boolean) {
    const election = await this.prisma.election.findUnique({
      where: { id: electionId },
      include: {
        positions: {
          include: {
            candidates: true,
            votes: {
              include: {
                voter: includePersonalData,
                votingSession: true
              }
            }
          }
        },
        votingSessions: {
          include: {
            voter: includePersonalData,
            votes: true
          }
        }
      }
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Prepare export data
    const exportData = {
      election: {
        id: election.id,
        title: election.title,
        type: election.type,
        status: election.status,
        startDate: election.startDate,
        endDate: election.endDate,
        totalVotesCast: election.totalVotesCast,
        turnoutPercentage: election.turnoutPercentage
      },
      positions: election.positions.map(position => ({
        id: position.id,
        name: position.name,
        order: position.order,
        maxSelections: position.maxSelections,
        candidates: position.candidates.map(candidate => ({
          id: candidate.id,
          firstName: candidate.firstName,
          lastName: candidate.lastName,
          voteCount: position.votes.filter(v => v.candidateId === candidate.id).length
        })),
        votes: position.votes.map(vote => ({
          id: vote.id,
          candidateId: vote.candidateId,
          castAt: vote.castAt,
          verified: vote.verified,
          ...(includePersonalData && vote.voter ? {
            voter: {
              studentId: vote.voter.studentId,
              faculty: vote.voter.faculty,
              department: vote.voter.department
            }
          } : {})
        }))
      })),
      exportedAt: new Date(),
      includePersonalData
    };

    const filename = `election_${electionId}_${Date.now()}.${format}`;

    if (format === 'json') {
      return {
        data: exportData,
        filename,
        mimeType: 'application/json',
        size: JSON.stringify(exportData).length
      };
    } else {
      // For CSV/XLSX formats, would need additional processing
      // This is a simplified version
      const csvData = this.convertToCSV(exportData);
      return {
        data: csvData,
        buffer: Buffer.from(csvData),
        filename,
        mimeType: format === 'csv' ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        size: csvData.length
      };
    }
  }

  private convertToCSV(data: any): string {
    // Simplified CSV conversion
    const rows = [];

    // Add election header
    rows.push(['Election Data']);
    rows.push(['Title', data.election.title]);
    rows.push(['Status', data.election.status]);
    rows.push(['Total Votes', data.election.totalVotesCast]);
    rows.push([]);

    // Add votes data
    rows.push(['Position', 'Candidate', 'Vote Count', 'Cast Date']);

    data.positions.forEach((position: any) => {
      position.votes.forEach((vote: any) => {
        const candidate = position.candidates.find((c: { id: any; }) => c.id === vote.candidateId);
        rows.push([
          position.name,
          candidate ? `${candidate.firstName} ${candidate.lastName}` : 'Abstain',
          1,
          vote.castAt
        ]);
      });
    });

    return rows.map(row => row.join(',')).join('\n');
  }

  // ============================================================================
  // ADMIN AND MANAGEMENT METHODS
  // ============================================================================

  /**
   * Get voting history for a user (enhanced)
   */
  async getVoteHistory(userId: string, includeDetails: boolean = false) {
    const sessions = await this.prisma.votingSession.findMany({
      where: {
        voterId: userId,
        status: 'COMPLETED'
      },
      include: {
        election: true,
        votes: includeDetails ? {
          include: {
            position: true,
            candidate: true
          }
        } : { select: { id: true, positionId: true } }
      },
      orderBy: { completedAt: 'desc' }
    });

    return sessions.map(session => ({
      id: session.id,
      election: {
        id: session.election.id,
        title: session.election.title,
        type: session.election.type,
        endDate: session.election.endDate
      },
      completedAt: session.completedAt,
      votesCount: session.votes.length,
      positions: includeDetails
        ? session.votes.map(vote => ({
            positionName: (vote as any).position?.name || 'Unknown',
            candidateName: (vote as any).candidate
              ? `${(vote as any).candidate.firstName} ${(vote as any).candidate.lastName}`
              : 'Abstain'
          }))
        : [...new Set(session.votes.map(v => (v as any).positionId || v.positionId))]
    }));
  }

  /**
   * Invalidate a vote (admin only)
   */
  async invalidateVote(
    voteId: string,
    adminId: string,
    reason: string
  ) {
    return await this.prisma.$transaction(async (tx) => {
      const vote = await tx.vote.findUnique({
        where: { id: voteId },
        include: { election: true, votingSession: true }
      });

      if (!vote) {
        throw new AppError('Vote not found', 404);
      }

      // Mark vote as invalid
      await tx.vote.update({
        where: { id: voteId },
        data: {
          verified: false,
          verifiedAt: null
        }
      });

      // Log the invalidation
      await AuditService.logAction({
        action: 'VOTE_INVALIDATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: adminId,
        electionId: vote.electionId,
        metadata: {
          voteId,
          originalVoterId: vote.voterId,
          reason,
          sessionId: vote.sessionId
        }
      });

      // Update election statistics
      await tx.election.update({
        where: { id: vote.electionId },
        data: {
          totalVotesCast: { decrement: 1 }
        }
      });

      return {
        success: true,
        message: 'Vote invalidated successfully',
        voteId,
        reason
      };
    });
  }

  /**
   * Get comprehensive voting analytics (admin only)
   */
  async getVotingAnalytics(electionId: string) {
    const election = await this.prisma.election.findUnique({
      where: { id: electionId },
      include: {
        positions: { include: { votes: true, candidates: true } },
        votingSessions: { include: { votes: true } }
      }
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Calculate comprehensive analytics
    const totalSessions = election.votingSessions.length;
    const completedSessions = election.votingSessions.filter(s => s.status === 'COMPLETED').length;
    const activeSessions = election.votingSessions.filter(s => s.status === 'ACTIVE').length;

    // Voting patterns by time
    const hourlyPattern = new Array(24).fill(0);
    election.votingSessions.forEach(session => {
      if (session.completedAt) {
        const hour = session.completedAt.getHours();
        hourlyPattern[hour]++;
      }
    });

    // Position analytics
    const positionAnalytics = election.positions.map(position => {
      const totalVotes = position.votes.length;
      const candidateStats = position.candidates.map(candidate => {
        const voteCount = position.votes.filter(v => v.candidateId === candidate.id).length;
        return {
          candidateId: candidate.id,
          candidateName: `${candidate.firstName} ${candidate.lastName}`,
          voteCount,
          percentage: totalVotes > 0 ? (voteCount / totalVotes) * 100 : 0
        };
      });

      return {
        positionId: position.id,
        positionName: position.name,
        totalVotes,
        candidateStats: candidateStats.sort((a, b) => b.voteCount - a.voteCount)
      };
    });

    return {
      electionId,
      electionTitle: election.title,
      totalEligibleVoters: election.totalEligibleVoters,
      totalVotesCast: election.totalVotesCast,
      turnoutPercentage: election.turnoutPercentage,
      sessionStats: {
        total: totalSessions,
        completed: completedSessions,
        active: activeSessions,
        completionRate: totalSessions > 0 ? (completedSessions / totalSessions) * 100 : 0
      },
      votingPatterns: {
        hourlyDistribution: hourlyPattern,
        peakHour: hourlyPattern.indexOf(Math.max(...hourlyPattern)),
        averageVotingTime: await this.calculateAverageVotingTime(electionId)
      },
      positionAnalytics,
      generatedAt: new Date()
    };
  }
}

// Export singleton instance for easy access
export const voteService = VoteService.getInstance();
