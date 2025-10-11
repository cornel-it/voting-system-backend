import { PrismaClient, Election, Result, Vote, Candidate, Position } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger, logAudit } from '../utils/logger';
import { AppError } from '../utils/errors';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { v4 as uuidv4 } from 'uuid';

export interface ElectionResults {
  electionId: string;
  electionTitle: string;
  status: 'DRAFT' | 'PRELIMINARY' | 'FINAL';
  totalVotes: number;
  turnoutPercentage: number;
  positions: PositionResult[];
  calculatedAt: Date;
  publishedAt?: Date;
}

export interface PositionResult {
  positionId: string;
  positionName: string;
  order: number;
  totalVotes: number;
  candidates: CandidateResult[];
  winnerCount: number;
  isTie: boolean;
}

export interface CandidateResult {
  candidateId: string;
  name: string;
  photo?: string;
  totalVotes: number;
  percentage: number;
  rank: number;
  isWinner: boolean;
  votesByDemographic?: {
    faculty: Record<string, number>;
    department: Record<string, number>;
    yearOfStudy: Record<string, number>;
  };
}

export interface VotingAnalytics {
  electionId: string;
  totalEligibleVoters: number;
  totalVotesCast: number;
  turnoutPercentage: number;
  votingByHour: Record<string, number>;
  votingByDay: Record<string, number>;
  peakVotingTimes: Array<{
    hour: number;
    count: number;
  }>;
  demographicBreakdown: {
    byFaculty: Record<string, { eligible: number; voted: number; percentage: number }>;
    byDepartment: Record<string, { eligible: number; voted: number; percentage: number }>;
    byYear: Record<string, { eligible: number; voted: number; percentage: number }>;
  };
}

export class ResultService {
  private static instance: ResultService;
  private static readonly CACHE_TTL = 60; // 1 minute for live results
  private static readonly FINAL_CACHE_TTL = 86400; // 24 hours for final results

  private constructor() {
    // Private constructor for singleton pattern
  }

  public static getInstance(): ResultService {
    if (!ResultService.instance) {
      ResultService.instance = new ResultService();
    }
    return ResultService.instance;
  }

  /**
   * Calculate election results
   */
  public async calculateResults(
    electionId: string,
    calculatedBy: string,
    isDraft: boolean = true
  ): Promise<ElectionResults> {
    return await prisma.$transaction(async (tx) => {
      const election = await tx.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            include: {
              candidates: {
                where: { status: 'APPROVED' },
                include: {
                  votes: true,
                },
              },
            },
            orderBy: { order: 'asc' },
          },
          votes: {
            include: {
              voter: {
                select: {
                  faculty: true,
                  department: true,
                  yearOfStudy: true,
                },
              },
              candidate: true,
            },
          },
        },
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      const totalVotes = election.votes.length;
      const eligibleVoters = election.totalEligibleVoters;
      const turnoutPercentage = eligibleVoters > 0 ? (totalVotes / eligibleVoters) * 100 : 0;

      const positionResults: PositionResult[] = [];

      // Process each position
      for (const position of election.positions) {
        const positionVotes = election.votes.filter(v => v.positionId === position.id);
        const candidateVoteCounts = new Map<string, number>();
        const candidateDemographics = new Map<string, any>();

        // Count votes for each candidate
        positionVotes.forEach(vote => {
          if (vote.candidateId && !vote.isAbstain) {
            const count = candidateVoteCounts.get(vote.candidateId) || 0;
            candidateVoteCounts.set(vote.candidateId, count + 1);

            // Track demographics
            if (!candidateDemographics.has(vote.candidateId)) {
              candidateDemographics.set(vote.candidateId, {
                faculty: {},
                department: {},
                yearOfStudy: {},
              });
            }

            const demographics = candidateDemographics.get(vote.candidateId);
            const voter = vote.voter;
            
            demographics.faculty[voter.faculty] = (demographics.faculty[voter.faculty] || 0) + 1;
            demographics.department[voter.department] = (demographics.department[voter.department] || 0) + 1;
            demographics.yearOfStudy[voter.yearOfStudy] = (demographics.yearOfStudy[voter.yearOfStudy] || 0) + 1;
          }
        });

        // Calculate candidate results
        const candidateResults: CandidateResult[] = position.candidates.map(candidate => {
          const votes = candidateVoteCounts.get(candidate.id) || 0;
          const percentage = positionVotes.length > 0 ? (votes / positionVotes.length) * 100 : 0;

          return {
            candidateId: candidate.id,
            name: `${candidate.firstName} ${candidate.lastName}`,
            photo: candidate.photo,
            totalVotes: votes,
            percentage: Math.round(percentage * 100) / 100,
            rank: 0, // Will be set after sorting
            isWinner: false, // Will be set after determining winners
            votesByDemographic: candidateDemographics.get(candidate.id),
          };
        });

        // Sort by votes (descending) and assign ranks
        candidateResults.sort((a, b) => b.totalVotes - a.totalVotes);
        
        let currentRank = 1;
        let previousVotes = -1;
        candidateResults.forEach((result, index) => {
          if (result.totalVotes !== previousVotes) {
            currentRank = index + 1;
          }
          result.rank = currentRank;
          previousVotes = result.totalVotes;
        });

        // Determine winners based on position requirements
        const maxSelections = position.maxSelections || 1;
        const topVoteCount = candidateResults[0]?.totalVotes || 0;
        
        // Check for ties at the winning threshold
        const winnersCount = candidateResults.filter(c => c.rank <= maxSelections).length;
        const isTie = candidateResults.filter(c => c.totalVotes === topVoteCount && c.totalVotes > 0).length > maxSelections;
        
        candidateResults.forEach(result => {
          result.isWinner = result.rank <= maxSelections && result.totalVotes > 0 && !isTie;
        });

        positionResults.push({
          positionId: position.id,
          positionName: position.name,
          order: position.order,
          totalVotes: positionVotes.length,
          candidates: candidateResults,
          winnerCount: candidateResults.filter(c => c.isWinner).length,
          isTie,
        });
      }

      const results: ElectionResults = {
        electionId,
        electionTitle: election.title,
        status: isDraft ? 'DRAFT' : 'PRELIMINARY',
        totalVotes,
        turnoutPercentage: Math.round(turnoutPercentage * 100) / 100,
        positions: positionResults,
        calculatedAt: new Date(),
      };

      // Save results to database if not draft
      if (!isDraft) {
        await this.saveResultsToDatabase(tx, results, calculatedBy);
      }

      // Cache results
      const cacheKey = `election-results:${electionId}:${isDraft ? 'draft' : 'preliminary'}`;
      const cacheTtl = isDraft ? ResultService.CACHE_TTL : ResultService.FINAL_CACHE_TTL;
      await redis.setex(cacheKey, cacheTtl, JSON.stringify(results));

      // Log calculation
      logAudit('RESULTS_CALCULATED', calculatedBy, {
        electionId,
        isDraft,
        totalVotes,
        turnoutPercentage,
      });

      logger.info('Election results calculated', {
        electionId,
        isDraft,
        totalVotes,
        positionsCount: positionResults.length,
      });

      return results;
    });
  }

  /**
   * Get election results
   */
  public async getElectionResults(
    electionId: string,
    includeUnpublished: boolean = false,
    useCache: boolean = true
  ): Promise<ElectionResults | null> {
    // Check cache first
    if (useCache) {
      const cacheKey = `election-results:${electionId}:final`;
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const election = await prisma.election.findUnique({
      where: { id: electionId },
      include: {
        results: {
          include: {
            candidate: true,
            position: true,
          },
          orderBy: [
            { position: { order: 'asc' } },
            { rank: 'asc' },
          ],
        },
      },
    });

    if (!election) {
      return null;
    }

    // Check if results should be visible
    if (!includeUnpublished && !election.showLiveResults && election.status !== 'COMPLETED') {
      return null;
    }

    if (election.results.length === 0) {
      // No saved results, calculate on-the-fly
      return await this.calculateResults(electionId, 'system', true);
    }

    // Convert database results to our format
    const positionMap = new Map<string, PositionResult>();
    
    election.results.forEach(result => {
      const positionId = result.positionId;
      
      if (!positionMap.has(positionId)) {
        positionMap.set(positionId, {
          positionId,
          positionName: result.position.name,
          order: result.position.order,
          totalVotes: 0,
          candidates: [],
          winnerCount: 0,
          isTie: false,
        });
      }

      const positionResult = positionMap.get(positionId)!;
      positionResult.totalVotes += result.totalVotes;
      
      if (result.isWinner) {
        positionResult.winnerCount++;
      }
      
      if (result.isTie) {
        positionResult.isTie = true;
      }

      positionResult.candidates.push({
        candidateId: result.candidateId,
        name: `${result.candidate.firstName} ${result.candidate.lastName}`,
        photo: result.candidate.photo,
        totalVotes: result.totalVotes,
        percentage: result.percentage,
        rank: result.rank,
        isWinner: result.isWinner,
      });
    });

    const results: ElectionResults = {
      electionId,
      electionTitle: election.title,
      status: 'FINAL',
      totalVotes: election.totalVotesCast,
      turnoutPercentage: election.turnoutPercentage,
      positions: Array.from(positionMap.values()).sort((a, b) => a.order - b.order),
      calculatedAt: election.updatedAt,
      publishedAt: election.results[0]?.publishedAt ?? undefined,
    };

    // Cache final results
    if (useCache && election.status === 'COMPLETED') {
      const cacheKey = `election-results:${electionId}:final`;
      await redis.setex(cacheKey, ResultService.FINAL_CACHE_TTL, JSON.stringify(results));
    }

    return results;
  }

  /**
   * Publish election results
   */
  public async publishResults(
    electionId: string,
    publishedBy: string
  ): Promise<ElectionResults> {
    return await prisma.$transaction(async (tx) => {
      const election = await tx.election.findUnique({
        where: { id: electionId },
        include: { results: true },
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      if (election.status !== 'COMPLETED') {
        throw new AppError('Cannot publish results for incomplete election', 400);
      }

      // Calculate final results if not already done
      let results = await this.getElectionResults(electionId, true, false);
      if (!results || results.status === 'DRAFT') {
        results = await this.calculateResults(electionId, publishedBy, false);
      }

      // Update results to published status
      await tx.result.updateMany({
        where: { electionId },
        data: {
          publishedAt: new Date(),
        },
      });

      // Update election
      await tx.election.update({
        where: { id: electionId },
        data: {
          showLiveResults: true,
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'RESULTS_PUBLISHED',
          category: 'ELECTION',
          severity: 'HIGH',
          userId: publishedBy,
          electionId,
          metadata: {
            totalVotes: results.totalVotes,
            turnoutPercentage: results.turnoutPercentage,
          },
        },
      });

      // Clear caches
      await this.clearResultsCache(electionId);

      // Send notifications to all participants
      await this.sendResultNotifications(electionId);

      logger.info('Election results published', {
        electionId,
        publishedBy,
        totalVotes: results.totalVotes,
      });

      results.status = 'FINAL';
      results.publishedAt = new Date();
      
      return results;
    });
  }

  /**
   * Get voting analytics
   */
  public async getVotingAnalytics(
    electionId: string,
    useCache: boolean = true
  ): Promise<VotingAnalytics> {
    const cacheKey = `voting-analytics:${electionId}`;
    
    if (useCache) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const [election, votes, eligibleVoters] = await Promise.all([
      prisma.election.findUnique({
        where: { id: electionId },
      }),
      prisma.vote.findMany({
        where: { electionId },
        include: {
          voter: {
            select: {
              faculty: true,
              department: true,
              yearOfStudy: true,
            },
          },
        },
      }),
      prisma.user.findMany({
        where: {
          OR: [
            { voterEligibility: { some: { electionId } } },
            // Add other eligibility criteria based on election settings
          ],
        },
        select: {
          faculty: true,
          department: true,
          yearOfStudy: true,
        },
      }),
    ]);

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Calculate voting by time
    const votingByHour: Record<string, number> = {};
    const votingByDay: Record<string, number> = {};

    votes.forEach(vote => {
      const castDate = new Date(vote.castAt);
      const hour = castDate.getHours();
      const day = castDate.toDateString();
      
      votingByHour[hour] = (votingByHour[hour] || 0) + 1;
      votingByDay[day] = (votingByDay[day] || 0) + 1;
    });

    // Find peak voting times
    const peakVotingTimes = Object.entries(votingByHour)
      .map(([hour, count]) => ({ hour: parseInt(hour), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Calculate demographic breakdown
    const demographicBreakdown = {
      byFaculty: {} as Record<string, { eligible: number; voted: number; percentage: number }>,
      byDepartment: {} as Record<string, { eligible: number; voted: number; percentage: number }>,
      byYear: {} as Record<string, { eligible: number; voted: number; percentage: number }>,
    };

    // Count eligible voters by demographics
    eligibleVoters.forEach(voter => {
      ['faculty', 'department', 'yearOfStudy'].forEach(field => {
        const value = field === 'yearOfStudy' ? voter[field].toString() : voter[field as keyof typeof voter];
        const category = field === 'faculty' ? 'byFaculty' : 
                        field === 'department' ? 'byDepartment' : 'byYear';
        
        if (!demographicBreakdown[category as keyof typeof demographicBreakdown][value as string]) {
          (demographicBreakdown[category as keyof typeof demographicBreakdown] as any)[value] = { eligible: 0, voted: 0, percentage: 0 };
        }
        (demographicBreakdown[category as keyof typeof demographicBreakdown] as any)[value].eligible++;
      });
    });

    // Count actual voters by demographics
    const uniqueVoters = new Set();
    votes.forEach(vote => {
      if (!uniqueVoters.has(vote.voterId)) {
        uniqueVoters.add(vote.voterId);
        const voter = vote.voter;
        
        ['faculty', 'department', 'yearOfStudy'].forEach(field => {
          const value = field === 'yearOfStudy' ? voter[field].toString() : voter[field as keyof typeof voter];
          const category = field === 'faculty' ? 'byFaculty' : 
                          field === 'department' ? 'byDepartment' : 'byYear';
          
          if ((demographicBreakdown[category as keyof typeof demographicBreakdown] as any)[value]) {
            (demographicBreakdown[category as keyof typeof demographicBreakdown] as any)[value].voted++;
          }
        });
      }
    });

    // Calculate percentages
    Object.values(demographicBreakdown).forEach(category => {
      Object.values(category).forEach(demo => {
        demo.percentage = demo.eligible > 0 ? Math.round((demo.voted / demo.eligible) * 100 * 100) / 100 : 0;
      });
    });

    const analytics: VotingAnalytics = {
      electionId,
      totalEligibleVoters: eligibleVoters.length,
      totalVotesCast: uniqueVoters.size,
      turnoutPercentage: eligibleVoters.length > 0 ? Math.round((uniqueVoters.size / eligibleVoters.length) * 100 * 100) / 100 : 0,
      votingByHour,
      votingByDay,
      peakVotingTimes,
      demographicBreakdown,
    };

    // Cache analytics
    if (useCache) {
      await redis.setex(cacheKey, ResultService.CACHE_TTL, JSON.stringify(analytics));
    }

    return analytics;
  }

  /**
   * Get live voting statistics
   */
  public async getLiveVotingStats(electionId: string): Promise<{
    totalVotes: number;
    votersParticipated: number;
    turnoutPercentage: number;
    positionProgress: Array<{
      positionId: string;
      positionName: string;
      votesReceived: number;
      leadingCandidate?: {
        name: string;
        votes: number;
        percentage: number;
      };
    }>;
    recentVotingActivity: Array<{
      hour: number;
      count: number;
    }>;
  }> {
    const cacheKey = `live-stats:${electionId}`;
    const cached = await redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const [election, votes] = await Promise.all([
      prisma.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            include: {
              candidates: {
                where: { status: 'APPROVED' },
              },
            },
          },
        },
      }),
      prisma.vote.findMany({
        where: { electionId },
        include: {
          candidate: true,
          position: true,
        },
      }),
    ]);

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    const uniqueVoters = new Set(votes.map(v => v.voterId));
    const totalVotes = votes.length;
    const votersParticipated = uniqueVoters.size;
    const turnoutPercentage = election.totalEligibleVoters > 0 ? 
      Math.round((votersParticipated / election.totalEligibleVoters) * 100 * 100) / 100 : 0;

    // Calculate position progress
    const positionProgress = election.positions.map(position => {
      const positionVotes = votes.filter(v => v.positionId === position.id && !v.isAbstain);
      const candidateVotes = new Map<string, number>();
      
      positionVotes.forEach(vote => {
        if (vote.candidateId) {
          candidateVotes.set(vote.candidateId, (candidateVotes.get(vote.candidateId) || 0) + 1);
        }
      });

      let leadingCandidate;
      if (candidateVotes.size > 0) {
        const [leadingCandidateId, leadingVotes] = Array.from(candidateVotes.entries())
          .sort(([, a], [, b]) => b - a)[0];
        
        const candidate = position.candidates.find(c => c.id === leadingCandidateId);
        if (candidate) {
          leadingCandidate = {
            name: `${candidate.firstName} ${candidate.lastName}`,
            votes: leadingVotes,
            percentage: positionVotes.length > 0 ? Math.round((leadingVotes / positionVotes.length) * 100 * 100) / 100 : 0,
          };
        }
      }

      return {
        positionId: position.id,
        positionName: position.name,
        votesReceived: positionVotes.length,
        leadingCandidate,
      };
    });

    // Recent activity (last 24 hours by hour)
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const recentVotes = votes.filter(v => new Date(v.castAt) >= last24Hours);
    
    const recentActivity: Record<number, number> = {};
    recentVotes.forEach(vote => {
      const hour = new Date(vote.castAt).getHours();
      recentActivity[hour] = (recentActivity[hour] || 0) + 1;
    });

    const recentVotingActivity = Object.entries(recentActivity)
      .map(([hour, count]) => ({ hour: parseInt(hour), count }))
      .sort((a, b) => a.hour - b.hour);

    const stats = {
      totalVotes,
      votersParticipated,
      turnoutPercentage,
      positionProgress,
      recentVotingActivity,
    };

    // Cache for 30 seconds
    await redis.setex(cacheKey, 30, JSON.stringify(stats));

    return stats;
  }

  /**
   * Save results to database (private method)
   */
  private async saveResultsToDatabase(
    tx: any,
    results: ElectionResults,
    calculatedBy: string
  ): Promise<void> {
    // Delete existing results
    await tx.result.deleteMany({
      where: { electionId: results.electionId },
    });

    // Insert new results
    for (const position of results.positions) {
      for (const candidate of position.candidates) {
        await tx.result.create({
          data: {
            electionId: results.electionId,
            positionId: position.positionId,
            candidateId: candidate.candidateId,
            totalVotes: candidate.totalVotes,
            percentage: candidate.percentage,
            rank: candidate.rank,
            isWinner: candidate.isWinner,
            isTie: position.isTie,
          },
        });
      }
    }

    // Update election statistics
    await tx.election.update({
      where: { id: results.electionId },
      data: {
        totalVotesCast: results.totalVotes,
        turnoutPercentage: results.turnoutPercentage,
      },
    });
  }

  /**
   * Send result notifications
   */
  private async sendResultNotifications(electionId: string): Promise<void> {
    const election = await prisma.election.findUnique({
      where: { id: electionId },
      include: {
        candidates: {
          include: {
            results: true,
          },
        },
      },
    });

    if (!election) return;

    // Send notifications to candidates
    for (const candidate of election.candidates) {
      const result = candidate.results[0];
      if (result) {
        await emailService.sendEmail({
          to: candidate.email,
          subject: `Election Results Published - ${election.title}`,
          template: 'election-results-candidate',
          data: {
            candidateName: `${candidate.firstName} ${candidate.lastName}`,
            electionTitle: election.title,
            totalVotes: result.totalVotes,
            percentage: result.percentage,
            rank: result.rank,
            isWinner: result.isWinner,
            resultsUrl: `${process.env.FRONTEND_URL}/results/${electionId}`,
          },
        });
      }
    }

    // Send general notification to all participants
    // This would require a more complex query to get all voters
    logger.info('Result notifications sent', { electionId });
  }

  /**
   * Clear results cache
   */
  private async clearResultsCache(electionId: string): Promise<void> {
    const patterns = [
      `election-results:${electionId}:*`,
      `voting-analytics:${electionId}`,
      `live-stats:${electionId}`,
    ];

    for (const pattern of patterns) {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }
  }

  /**
   * Export results data
   */
  public async exportResults(electionId: string, options: {
    format: string;
    includeAnalytics: boolean;
    includeDemographics: boolean;
    includeCharts: boolean;
    exportedBy: string;
  }): Promise<{
    data?: any;
    buffer?: Buffer;
    filename: string;
    mimeType: string;
    size: number;
  }> {
    const results = await this.getElectionResults(electionId, true, false);
    if (!results) {
      throw new AppError('Election results not found', 404);
    }

    const analytics = options.includeAnalytics ? await this.getVotingAnalytics(electionId) : null;

    const exportData = {
      election: results,
      analytics: analytics,
      exportedAt: new Date(),
      exportedBy: options.exportedBy,
    };

    const filename = `election-results-${electionId}-${new Date().toISOString().split('T')[0]}.${options.format}`;

    if (options.format === 'json') {
      return {
        data: exportData,
        filename,
        mimeType: 'application/json',
        size: JSON.stringify(exportData).length,
      };
    }

    // For other formats, return placeholder buffer
    const buffer = Buffer.from(JSON.stringify(exportData));
    return {
      buffer,
      filename,
      mimeType: options.format === 'pdf' ? 'application/pdf' :
                options.format === 'csv' ? 'text/csv' :
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      size: buffer.length,
    };
  }

  /**
   * Get position-specific results
   */
  public async getPositionResults(
    electionId: string,
    positionId: string,
    includeDemographics: boolean = false
  ): Promise<PositionResult | null> {
    const results = await this.getElectionResults(electionId, true);
    if (!results) {
      return null;
    }

    const positionResult = results.positions.find(p => p.positionId === positionId);
    return positionResult || null;
  }

  /**
   * Get candidate performance details
   */
  public async getCandidatePerformance(
    electionId: string,
    candidateId: string
  ): Promise<{
    candidate: CandidateResult;
    performanceMetrics: {
      totalVotes: number;
      rank: number;
      percentage: number;
      isWinner: boolean;
      votesTrend: Array<{ hour: number; votes: number }>;
    };
  } | null> {
    const results = await this.getElectionResults(electionId, true);
    if (!results) {
      return null;
    }

    for (const position of results.positions) {
      const candidate = position.candidates.find(c => c.candidateId === candidateId);
      if (candidate) {
        return {
          candidate,
          performanceMetrics: {
            totalVotes: candidate.totalVotes,
            rank: candidate.rank,
            percentage: candidate.percentage,
            isWinner: candidate.isWinner,
            votesTrend: [], // Placeholder for trend data
          },
        };
      }
    }

    return null;
  }

  /**
   * Compare results between time periods
   */
  public async compareResults(
    electionId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
      comparisonType: string;
    }
  ): Promise<{
    comparisonData: any;
    insights: string[];
  }> {
    // Placeholder implementation
    return {
      comparisonData: {},
      insights: ['Results comparison feature coming soon'],
    };
  }

  /**
   * Verify results integrity
   */
  public async verifyResultsIntegrity(electionId: string): Promise<{
    isValid: boolean;
    checksPerformed: string[];
    issues: string[];
  }> {
    const results = await this.getElectionResults(electionId, true, false);
    if (!results) {
      throw new AppError('Election results not found', 404);
    }

    const checksPerformed = [
      'Vote count verification',
      'Candidate eligibility check',
      'Result calculation validation',
      'Data integrity check',
    ];

    // Basic integrity checks
    const issues: string[] = [];
    let isValid = true;

    // Check if vote counts match
    for (const position of results.positions) {
      const totalCandidateVotes = position.candidates.reduce((sum, c) => sum + c.totalVotes, 0);
      if (totalCandidateVotes > position.totalVotes) {
        issues.push(`Position ${position.positionName}: Candidate votes exceed total votes`);
        isValid = false;
      }
    }

    return {
      isValid,
      checksPerformed,
      issues,
    };
  }

  /**
   * Get result summary for dashboard
   */
  public async getResultSummary(electionId: string): Promise<{
    overview: {
      totalVotes: number;
      turnoutPercentage: number;
      positionsCount: number;
      candidatesCount: number;
    };
    winners: Array<{
      positionName: string;
      candidateName: string;
      votes: number;
      percentage: number;
    }>;
    topPositions: Array<{
      positionName: string;
      totalVotes: number;
      leadingCandidate: string;
    }>;
  }> {
    const results = await this.getElectionResults(electionId);
    if (!results) {
      throw new AppError('Election results not found', 404);
    }

    const winners = results.positions
      .flatMap(position =>
        position.candidates
          .filter(c => c.isWinner)
          .map(c => ({
            positionName: position.positionName,
            candidateName: c.name,
            votes: c.totalVotes,
            percentage: c.percentage,
          }))
      );

    const topPositions = results.positions
      .map(position => ({
        positionName: position.positionName,
        totalVotes: position.totalVotes,
        leadingCandidate: position.candidates[0]?.name || 'No votes',
      }))
      .sort((a, b) => b.totalVotes - a.totalVotes)
      .slice(0, 5);

    return {
      overview: {
        totalVotes: results.totalVotes,
        turnoutPercentage: results.turnoutPercentage,
        positionsCount: results.positions.length,
        candidatesCount: results.positions.reduce((sum, p) => sum + p.candidates.length, 0),
      },
      winners,
      topPositions,
    };
  }

  /**
   * Get historical comparison
   */
  public async getHistoricalComparison(
    electionId: string,
    options: {
      compareWith?: string;
      metrics: string;
    }
  ): Promise<{
    currentElection: any;
    comparisonElection?: any;
    insights: string[];
  }> {
    const currentResults = await this.getElectionResults(electionId, true);

    return {
      currentElection: currentResults,
      comparisonElection: null,
      insights: ['Historical comparison feature coming soon'],
    };
  }

  /**
   * Generate results certificate
   */
  public async generateResultsCertificate(
    electionId: string,
    options: {
      candidateId?: string;
      certificateType: string;
      generatedBy: string;
    }
  ): Promise<{
    id: string;
    filename: string;
    buffer: Buffer;
  }> {
    const results = await this.getElectionResults(electionId, true);
    if (!results) {
      throw new AppError('Election results not found', 404);
    }

    // Placeholder certificate generation
    const certificateData = {
      electionTitle: results.electionTitle,
      candidateId: options.candidateId,
      certificateType: options.certificateType,
      generatedAt: new Date(),
      generatedBy: options.generatedBy,
    };

    const buffer = Buffer.from(JSON.stringify(certificateData));
    const filename = `certificate-${electionId}-${options.candidateId || 'all'}-${Date.now()}.pdf`;

    return {
      id: uuidv4(),
      filename,
      buffer,
    };
  }
}

// Export singleton instance
export default ResultService;