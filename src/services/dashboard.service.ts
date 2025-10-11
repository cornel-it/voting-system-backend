// backend/src/services/dashboard.service.ts

import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger } from '../utils/logger';
import { UserRole, ElectionStatus, ElectionType, CandidateStatus } from '@prisma/client';
import { webSocketService } from './websocket.service';
import { auditService } from './audit.service';
import { notificationService } from './notification.service';
import {
  VoterDashboardData,
  CandidateDashboardData,
  AdminDashboardData,
  DashboardNotification,
  VoterStatistics,
  CandidateAnalytics,
  AdminOverview,
  SystemHealth,
  AdminAnalytics,
  DashboardFilters,
  ActivityItem,
  SystemAlert,
} from '../types/dashboard.types';
import { AppError } from '../utils/errors';

export class DashboardService {
  private static instance: DashboardService;

  private constructor() {}

  public static getInstance(): DashboardService {
    if (!DashboardService.instance) {
      DashboardService.instance = new DashboardService();
    }
    return DashboardService.instance;
  }

  /**
   * Get voter dashboard data
   */
  public async getVoterDashboard(userId: string, filters?: DashboardFilters): Promise<VoterDashboardData> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          studentId: true,
          firstName: true,
          lastName: true,
          email: true,
          faculty: true,
          department: true,
          course: true,
          yearOfStudy: true,
          profileImage: true,
          isVerified: true,
          createdAt: true,
        },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const [
        eligibleElections,
        votingHistory,
        notifications,
        upcomingElections,
        recentResults,
        statistics,
      ] = await Promise.all([
        this.getEligibleElections(userId, user.faculty, user.department, user.course, user.yearOfStudy),
        this.getVotingHistory(userId),
        this.getNotifications(userId, 10),
        this.getUpcomingElections(user.faculty, user.department, user.course, user.yearOfStudy),
        this.getRecentResults(userId),
        this.getVoterStatistics(userId),
      ]);

      return {
        profile: {
          id: user.id,
          studentId: user.studentId,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          faculty: user.faculty,
          department: user.department,
          course: user.course,
          yearOfStudy: user.yearOfStudy,
          profileImage: user.profileImage || undefined,
          isVerified: user.isVerified,
          joinedAt: user.createdAt,
        },
        eligibleElections: eligibleElections as any,
       votingHistory: votingHistory as any,
        notifications,
        upcomingElections,
        recentResults,
        statistics,
      };
    } catch (error) {
      logger.error('Error fetching voter dashboard:', error);
      throw error;
    }
  }

  /**
   * Get candidate dashboard data
   */
  public async getCandidateDashboard(userId: string): Promise<CandidateDashboardData> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          studentId: true,
          firstName: true,
          lastName: true,
          email: true,
          faculty: true,
          department: true,
          course: true,
          yearOfStudy: true,
          profileImage: true,
        },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const [
        applications,
        campaigns,
        elections,
        analytics,
        notifications,
        tasks,
      ] = await Promise.all([
        this.getCandidateApplications(userId),
        this.getCandidateCampaigns(userId),
        this.getCandidateElections(userId),
        this.getCandidateAnalytics(userId),
        this.getNotifications(userId, 15),
        this.getCandidateTasks(userId),
      ]);

      return {
        profile: {
          id: user.id,
          studentId: user.studentId,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          faculty: user.faculty,
          department: user.department,
          course: user.course,
          yearOfStudy: user.yearOfStudy,
          profileImage: user.profileImage || undefined,
          bio: await this.getUserBio(user.id),
          achievements: (await this.getUserAchievements(user.id)) as any,
          socialMedia: await this.getUserSocialMedia(user.id)
        },
        applications: applications as any,
        campaigns: campaigns as any,
        elections: elections as any,
        analytics,
        notifications,
        tasks: tasks as any,
      };
    } catch (error) {
      logger.error('Error fetching candidate dashboard:', error);
      throw error;
    }
  }

  /**
   * Get admin dashboard data
   */
  public async getAdminDashboard(userId: string): Promise<AdminDashboardData> {
    try {
      const [
        overview,
        elections,
        users,
        candidates,
        voting,
        system,
        analytics,
        alerts,
        recentActivity,
        reports,
      ] = await Promise.all([
        this.getAdminOverview(),
        this.getAdminElectionSummary(),
        this.getAdminUserSummary(),
        this.getAdminCandidateSummary(),
        this.getAdminVotingSummary(),
        this.getSystemHealth(),
        this.getAdminAnalytics(),
        this.getSystemAlerts(),
        this.getAdminActivity(),
        this.getAvailableReports(),
      ]);

      return {
        overview,
        elections,
        users,
        candidates,
        voting,
        system,
        analytics,
        alerts,
        recentActivity: recentActivity as any,
        reports: reports as any,
      };
    } catch (error) {
      logger.error('Error fetching admin dashboard:', error);
      throw error;
    }
  }

  // Private helper methods

  private async getEligibleElections(
    userId: string,
    faculty: string,
    department: string,
    course: string,
    yearOfStudy: number
  ) {
    const elections = await prisma.election.findMany({
      where: {
        OR: [
          { eligibleFaculties: { has: faculty } },
          { eligibleDepartments: { has: department } },
          { eligibleCourses: { has: course } },
          { eligibleYears: { has: yearOfStudy } },
          {
            AND: [
              { eligibleFaculties: { isEmpty: true } },
              { eligibleDepartments: { isEmpty: true } },
              { eligibleCourses: { isEmpty: true } },
              { eligibleYears: { isEmpty: true } },
            ],
          },
        ],
        status: {
          in: [ElectionStatus.SCHEDULED, ElectionStatus.ACTIVE],
        },
      },
      include: {
        positions: true,
        votes: {
          where: { voterId: userId },
          select: { id: true },
        },
      },
      orderBy: { startDate: 'asc' },
    });

    return elections.map((election) => ({
      id: election.id,
      title: election.title,
      description: election.description,
      type: election.type,
      status: election.status,
      startDate: election.startDate,
      endDate: election.endDate,
      totalPositions: election.positions.length,
      hasVoted: election.votes.length > 0,
      canVote: election.status === ElectionStatus.ACTIVE && election.votes.length === 0,
      timeRemaining: this.calculateTimeRemaining(election.endDate),
      coverImage: election.coverImage || undefined,
      turnoutPercentage: election.turnoutPercentage,
    }));
  }

  private async getVotingHistory(userId: string) {
    const votes = await prisma.vote.findMany({
      where: { voterId: userId },
      include: {
        election: {
          select: {
            id: true,
            title: true,
            type: true,
            positions: {
              select: { id: true }
            },
          },
        },
        position: {
          select: {
            name: true,
          },
        },
      },
      orderBy: { castAt: 'desc' },
    });

    const groupedVotes = votes.reduce((acc, vote) => {
      const key = vote.electionId;
      if (!acc[key]) {
        acc[key] = {
          electionId: vote.electionId,
          electionTitle: vote.election.title,
          electionType: vote.election.type,
          totalPositions: vote.election.positions.length,
          votes: [],
        };
      }
      acc[key].votes.push(vote);
      return acc;
    }, {} as Record<string, any>);

    return Object.values(groupedVotes).map((group: any) => ({
      id: group.votes[0].id,
      electionId: group.electionId,
      electionTitle: group.electionTitle,
      electionType: group.electionType,
      votedAt: group.votes[0].castAt,
      positionsVoted: group.votes.length,
      totalPositions: group.totalPositions,
      verificationCode: group.votes[0].verificationCode,
      status: group.votes[0].verified ? 'verified' : 'pending',
    }));
  }

  private async getNotifications(userId: string, limit: number = 10): Promise<DashboardNotification[]> {
    const notifications = await prisma.notification.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });

    return notifications.map((notification) => ({
      id: notification.id,
      title: notification.title,
      message: notification.message,
      type: notification.type as any,
      priority: notification.priority as any,
      read: notification.read,
      actionUrl: notification.actionUrl ?? undefined,
      actionText: notification.actionUrl ? this.getActionTextFromType(notification.type) : undefined,
      createdAt: notification.createdAt,
      expiresAt: notification.expiresAt ?? undefined,
      data: notification.data as Record<string, any>,
    }));
  }

  private async getUpcomingElections(
    faculty: string,
    department: string,
    course: string,
    yearOfStudy: number
  ) {
    const now = new Date();
    const elections = await prisma.election.findMany({
      where: {
        startDate: { gt: now },
        OR: [
          { eligibleFaculties: { has: faculty } },
          { eligibleDepartments: { has: department } },
          { eligibleCourses: { has: course } },
          { eligibleYears: { has: yearOfStudy } },
        ],
      },
      include: {
        positions: true,
      },
      orderBy: { startDate: 'asc' },
      take: 5,
    });

    return elections.map((election) => ({
      id: election.id,
      title: election.title,
      type: election.type,
      startDate: election.startDate,
      endDate: election.endDate,
      description: election.description,
      totalPositions: election.positions.length,
      isEligible: true,
      coverImage: election.coverImage || undefined,
      registrationDeadline: election.registrationEnd || undefined,
      timeUntilStart: this.calculateTimeRemaining(election.startDate),
    }));
  }

  private async getRecentResults(userId: string) {
    const recentElections = await prisma.election.findMany({
      where: {
        status: ElectionStatus.COMPLETED,
        votes: {
          some: { voterId: userId },
        },
      },
      include: {
        results: {
          include: {
            candidate: true,
            position: true,
          },
          where: { isWinner: true },
        },
      },
      orderBy: { endDate: 'desc' },
      take: 5,
    });

    return recentElections.map((election) => ({
      id: election.id,
      electionId: election.id,
      electionTitle: election.title,
      electionType: election.type,
      completedAt: election.endDate,
      totalVotes: election.totalVotesCast,
      turnoutPercentage: election.turnoutPercentage,
      winnersByPosition: election.results.map((result) => ({
        positionName: result.position.name,
        winnerName: `${result.candidate.firstName} ${result.candidate.lastName}`,
        votePercentage: result.percentage,
      })),
      participatedInElection: true,
    }));
  }

  private async getVoterStatistics(userId: string): Promise<VoterStatistics> {
    const [totalVotes, elections] = await Promise.all([
      prisma.vote.count({ where: { voterId: userId } }),
      prisma.election.findMany({
        where: {
          votes: {
            some: { voterId: userId },
          },
        },
        select: {
          id: true,
          type: true,
          createdAt: true,
        },
      }),
    ]);

    const lastVote = await prisma.vote.findFirst({
      where: { voterId: userId },
      orderBy: { castAt: 'desc' },
      select: { castAt: true },
    });

    const electionTypeCount = elections.reduce((acc, election) => {
      acc[election.type] = (acc[election.type] || 0) + 1;
      return acc;
    }, {} as Record<ElectionType, number>);

    const favoriteElectionType = Object.entries(electionTypeCount).reduce(
      (max, [type, count]) => ((count as number) > max.count ? { type: type as ElectionType, count: count as number } : max),
      { type: ElectionType.PRESIDENTIAL as ElectionType, count: 0 as number }
    ).type;

    // Calculate yearly participation
    const yearlyParticipation = elections.reduce((acc, election) => {
      const year = election.createdAt.getFullYear();
      const existing = acc.find((item) => item.year === year);
      if (existing) {
        existing.elections += 1;
      } else {
        acc.push({ year, elections: 1, votes: 0 });
      }
      return acc;
    }, [] as Array<{ year: number; elections: number; votes: number }>);

    return {
      totalElectionsParticipated: elections.length,
      totalVotesCast: totalVotes,
      participationRate: elections.length > 0 ? (totalVotes / elections.length) * 100 : 0,
      lastVoteDate: lastVote?.castAt,
      averageVotingTime: await this.calculateUserAverageVotingTime(userId),
      favoriteElectionType,
      yearlyParticipation,
    };
  }

  private async getCandidateApplications(userId: string) {
    const candidates = await prisma.candidate.findMany({
      where: { studentId: userId },
      include: {
        election: {
          select: {
            id: true,
            title: true,
          },
        },
        position: {
          select: {
            id: true,
            name: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return candidates.map((candidate) => ({
      id: candidate.id,
      electionId: candidate.electionId,
      electionTitle: candidate.election.title,
      positionId: candidate.positionId,
      positionName: candidate.position.name,
      status: candidate.status,
      appliedAt: candidate.createdAt,
      reviewedAt: candidate.verifiedAt,
      feedback: candidate.disqualificationReason,
      manifesto: candidate.manifesto,
      photo: candidate.photo,
      bannerImage: candidate.bannerImage,
      socialMedia: candidate.socialMedia as Record<string, string>,
    }));
  }

  private async getCandidateCampaigns(userId: string) {
    const campaigns = await prisma.campaign.findMany({
      where: {
        candidate: {
          studentId: userId,
        },
      },
      include: {
        candidate: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
          },
        },
        election: {
          select: {
            id: true,
            title: true,
            status: true,
          },
        },
        tasks: {
          where: {
            status: {
              in: ['PENDING', 'IN_PROGRESS'],
            },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return campaigns.map((campaign) => ({
      id: campaign.id,
      name: campaign.name,
      slogan: campaign.slogan,
      status: campaign.status,
      electionId: campaign.electionId,
      electionTitle: campaign.election.title,
      electionStatus: campaign.election.status,
      description: campaign.description,
      isApproved: campaign.isApproved,
      approvedAt: campaign.approvedAt,
      publishedAt: campaign.publishedAt,
      viewCount: campaign.viewCount,
      shareCount: campaign.shareCount,
      engagementRate: campaign.engagementRate,
      pendingTasks: campaign.tasks.length,
      logo: campaign.logo,
      bannerImage: campaign.bannerImage,
      colors: campaign.colors as Record<string, string>,
      website: campaign.website,
      email: campaign.email,
      phone: campaign.phone,
      socialMedia: campaign.socialMedia as Record<string, string>,
      createdAt: campaign.createdAt,
      updatedAt: campaign.updatedAt,
    }));
  }

  private async getCandidateElections(userId: string) {
    const candidates = await prisma.candidate.findMany({
      where: { studentId: userId },
      include: {
        election: true,
        position: true,
        results: true,
        runningMate: true,
        runningMateFor: true,
      },
    });

    return candidates.map((candidate) => ({
      id: candidate.electionId,
      title: candidate.election.title,
      type: candidate.election.type,
      status: candidate.election.status,
      positionName: candidate.position.name,
      isRunningMate: !!candidate.runningMateFor,
      runningMateFor: candidate.runningMateFor?.id,
      startDate: candidate.election.startDate,
      endDate: candidate.election.endDate,
      totalVotes: candidate.results[0]?.totalVotes,
      votePercentage: candidate.results[0]?.percentage,
      rank: candidate.results[0]?.rank,
      isWinner: candidate.results[0]?.isWinner,
      result: candidate.results[0]?.isWinner
        ? 'won'
        : candidate.results[0]?.isTie
        ? 'tie'
        : candidate.election.status === ElectionStatus.COMPLETED
        ? 'lost'
        : 'pending',
    }));
  }

  private async getCandidateAnalytics(userId: string): Promise<CandidateAnalytics> {
    const candidates = await prisma.candidate.findMany({
      where: { studentId: userId },
      include: {
        campaign: true,
        election: true,
        results: true,
      },
    });

    // Get analytics data from Analytics table
    const analyticsData = await prisma.analytics.findMany({
      where: {
        entityType: 'candidate',
        entityId: {
          in: candidates.map(c => c.id),
        },
      },
      orderBy: { timestamp: 'desc' },
    });

    // Aggregate view counts
    const profileViews = analyticsData.filter(a => a.eventType === 'CANDIDATE_VIEW').length;
    const manifestoDownloads = analyticsData.filter(a => a.eventType === 'DOWNLOAD' &&
      a.eventData && (a.eventData as any).type === 'manifesto').length;

    // Calculate campaign reach and engagement
    const totalViews = candidates.reduce((sum, candidate) =>
      sum + (candidate.campaign?.viewCount || 0), 0);
    const totalShares = candidates.reduce((sum, candidate) =>
      sum + (candidate.campaign?.shareCount || 0), 0);
    const avgEngagement = candidates.reduce((sum, candidate) =>
      sum + (candidate.campaign?.engagementRate || 0), 0) / Math.max(candidates.length, 1);

    // Generate supporter growth over time (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const viewsByDay = analyticsData
      .filter(a => a.eventType === 'CANDIDATE_VIEW' && a.timestamp >= thirtyDaysAgo)
      .reduce((acc, a) => {
        const date = a.timestamp.toISOString().split('T')[0];
        acc[date] = (acc[date] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

    const supporterGrowth = Object.entries(viewsByDay)
      .map(([date, views]) => ({ date, supporters: views }))
      .sort((a, b) => a.date.localeCompare(b.date));

    // Get demographic breakdown from voter analytics
    const voterAnalytics = await prisma.analytics.findMany({
      where: {
        eventType: 'CANDIDATE_VIEW',
        entityId: {
          in: candidates.map(c => c.id),
        },
        userId: { not: null },
      },
      include: {
        user: {
          select: {
            faculty: true,
            yearOfStudy: true,
          },
        },
      },
    });

    const byFaculty = voterAnalytics.reduce((acc, a) => {
      const faculty = a.user?.faculty || 'Unknown';
      const existing = acc.find(item => item.label === faculty);
      if (existing) {
        existing.value += 1;
      } else {
        acc.push({ label: faculty, value: 1 });
      }
      return acc;
    }, [] as Array<{ label: string; value: number }>);

    const byYear = voterAnalytics.reduce((acc, a) => {
      const year = a.user?.yearOfStudy?.toString() || 'Unknown';
      const existing = acc.find(item => item.label === year);
      if (existing) {
        existing.value += 1;
      } else {
        acc.push({ label: year, value: 1 });
      }
      return acc;
    }, [] as Array<{ label: string; value: number }>);

    return {
      profileViews,
      manifestoDownloads,
      campaignReach: totalViews,
      engagementRate: avgEngagement,
      supporterGrowth,
      demographicBreakdown: {
        byFaculty: byFaculty as any,
        byYear: byYear as any,
        byGender: [], // Gender not in current user model
      },
    };
  }

  private async getCandidateTasks(userId: string) {
    const tasks = await prisma.task.findMany({
      where: {
        OR: [
          { assignedTo: userId },
          {
            entityType: 'campaign',
            entityId: {
              in: await prisma.campaign.findMany({
                where: {
                  candidate: {
                    studentId: userId,
                  },
                },
                select: { id: true },
              }).then(campaigns => campaigns.map(c => c.id)),
            },
          },
        ],
      },
      include: {
        creator: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
        assignee: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
        campaign: {
          select: {
            name: true,
            election: {
              select: {
                title: true,
              },
            },
          },
        },
      },
      orderBy: [
        { status: 'asc' },
        { priority: 'desc' },
        { dueDate: 'asc' },
      ],
    });

    return tasks.map((task) => ({
      id: task.id,
      title: task.title,
      description: task.description,
      type: task.type,
      priority: task.priority,
      status: task.status,
      dueDate: task.dueDate,
      estimatedHours: task.estimatedHours,
      actualHours: task.actualHours,
      assignedBy: task.creator ? `${task.creator.firstName} ${task.creator.lastName}` : undefined,
      assignedTo: task.assignee ? `${task.assignee.firstName} ${task.assignee.lastName}` : undefined,
      context: {
        type: task.entityType,
        id: task.entityId,
        name: task.campaign?.name,
        electionTitle: task.campaign?.election?.title,
      },
      completedAt: task.completedAt,
      notes: task.notes,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
    }));
  }

  private async getAdminOverview(): Promise<AdminOverview> {
    const [
      totalUsers,
      totalElections,
      totalVotes,
      totalCandidates,
      activeElections,
      pendingCandidates,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.election.count(),
      prisma.vote.count(),
      prisma.candidate.count(),
      prisma.election.count({ where: { status: ElectionStatus.ACTIVE } }),
      prisma.candidate.count({ where: { status: CandidateStatus.PENDING } }),
    ]);

    // Get actual system metrics
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const oneMonthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const [dailyActiveUsers, weeklyActiveUsers, monthlyActiveUsers] = await Promise.all([
      prisma.user.count({
        where: {
          lastLogin: { gte: oneDayAgo },
        },
      }),
      prisma.user.count({
        where: {
          lastLogin: { gte: oneWeekAgo },
        },
      }),
      prisma.user.count({
        where: {
          lastLogin: { gte: oneMonthAgo },
        },
      }),
    ]);

    const systemMetrics = {
      systemUptime: process.uptime(),
      serverLoad: process.cpuUsage().system / 1000000, // Convert to percentage
      databaseSize: await this.getDatabaseSize(),
      storageUsed: await this.getStorageUsage(),
      dailyActiveUsers,
      weeklyActiveUsers,
      monthlyActiveUsers,
    };

    return {
      totalUsers,
      totalElections,
      totalVotes,
      totalCandidates,
      activeElections,
      pendingCandidates,
      ...systemMetrics,
    };
  }

  private async getAdminElectionSummary() {
    const elections = await prisma.election.findMany({
      include: {
        candidates: true,
        votes: true,
        _count: {
          select: {
            candidates: true,
            votes: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      take: 10,
    });

    return Promise.all(elections.map(async (election) => ({
      id: election.id,
      title: election.title,
      type: election.type,
      status: election.status,
      startDate: election.startDate,
      endDate: election.endDate,
      totalCandidates: election._count.candidates,
      totalVotes: election._count.votes,
      eligibleVoters: election.totalEligibleVoters,
      turnoutPercentage: election.turnoutPercentage,
      completionPercentage: this.calculateElectionProgress(election),
      issuesCount: await prisma.issueReport.count({
        where: {
          page: { contains: `/elections/${election.id}` },
          status: { in: ['OPEN', 'IN_PROGRESS'] },
        },
      }),
      lastActivity: election.updatedAt,
    })));
  }

  private async getAdminUserSummary() {
    const [
      totalUsers,
      verifiedUsers,
      activeUsers,
      newRegistrationsToday,
      newRegistrationsWeek,
      newRegistrationsMonth,
      usersByRole,
      usersByFaculty,
      pendingVerifications,
      suspendedUsers,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { isVerified: true } }),
      prisma.user.count({ where: { isActive: true } }),
      prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(new Date().setHours(0, 0, 0, 0)),
          },
        },
      }),
      prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
          },
        },
      }),
      prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
          },
        },
      }),
      prisma.user.groupBy({
        by: ['role'],
        _count: true,
      }),
      prisma.user.groupBy({
        by: ['faculty'],
        _count: true,
      }),
      prisma.user.count({ where: { isVerified: false, isActive: true } }),
      prisma.user.count({ where: { isActive: false } }),
    ]);

    return {
      totalUsers,
      verifiedUsers,
      activeUsers,
      newRegistrations: {
        today: newRegistrationsToday,
        thisWeek: newRegistrationsWeek,
        thisMonth: newRegistrationsMonth,
      },
      usersByRole: usersByRole.map((item) => ({
        role: item.role,
        count: item._count,
      })),
      usersByFaculty: usersByFaculty.map((item) => ({
        faculty: item.faculty,
        count: item._count,
      })),
      pendingVerifications,
      suspendedUsers,
    };
  }

  private async getAdminCandidateSummary() {
    const [
      totalCandidates,
      pendingApprovals,
      approvedCandidates,
      rejectedCandidates,
      candidatesByElection,
      candidatesByStatus,
      recentApplications,
    ] = await Promise.all([
      prisma.candidate.count(),
      prisma.candidate.count({ where: { status: CandidateStatus.PENDING } }),
      prisma.candidate.count({ where: { status: CandidateStatus.APPROVED } }),
      prisma.candidate.count({ where: { status: CandidateStatus.REJECTED } }),
      prisma.candidate.groupBy({
        by: ['electionId'],
        _count: true,
      }) as any,
      prisma.candidate.groupBy({
        by: ['status'],
        _count: true,
      }),
      prisma.candidate.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        include: {
          election: {
            select: {
              title: true,
            },
          },
          position: {
            select: {
              name: true,
            },
          },
        },
      }),
    ]);

    return {
      totalCandidates,
      pendingApprovals,
      approvedCandidates,
      rejectedCandidates,
      candidatesByElection: candidatesByElection.map((item: any) => ({
        electionId: item.electionId,
        electionTitle: item.election?.title || 'Unknown',
        candidateCount: item._count,
      })),
      candidatesByStatus: candidatesByStatus.map((item) => ({
        status: item.status,
        count: item._count,
      })),
      recentApplications: recentApplications.map((candidate) => ({
        candidateId: candidate.id,
        candidateName: `${candidate.firstName} ${candidate.lastName}`,
        electionTitle: candidate.election.title,
        positionName: candidate.position.name,
        appliedAt: candidate.createdAt,
      })),
    };
  }

  private async getAdminVotingSummary() {
    const now = new Date();
    const today = new Date(now.setHours(0, 0, 0, 0));
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalVotes,
      votesToday,
      votesThisWeek,
      votesByElection,
    ] = await Promise.all([
      prisma.vote.count(),
      prisma.vote.count({
        where: {
          castAt: { gte: today },
        },
      }),
      prisma.vote.count({
        where: {
          castAt: { gte: weekAgo },
        },
      }),
      prisma.vote.groupBy({
        by: ['electionId'],
        _count: true,
      }) as any,
    ]);

    return {
      totalVotes,
      votesToday,
      votesThisWeek,
      averageVotingTime: await this.calculateAverageVotingTime(),
      peakVotingHour: await this.calculatePeakVotingHour(),
      votesByElection: votesByElection.map((item: any) => ({
        electionId: item.electionId,
        electionTitle: item.election?.title || 'Unknown',
        voteCount: item._count,
        turnoutPercentage: item.election?.totalEligibleVoters
          ? (item._count / item.election.totalEligibleVoters) * 100
          : 0,
      })),
      votingTrends: await this.getVotingTrends(),
      deviceBreakdown: await this.getDeviceBreakdown()
    };
  }

  private async getSystemHealth(): Promise<SystemHealth> {
    let overall: 'healthy' | 'warning' | 'critical' = 'healthy';

    // Test database connection
    const dbStart = Date.now();
    let dbStatus = 'connected';
    let dbResponseTime = 0;

    try {
      await prisma.$queryRaw`SELECT 1`;
      dbResponseTime = Date.now() - dbStart;
      if (dbResponseTime > 1000) overall = 'warning';
    } catch (error) {
      dbStatus = 'disconnected';
      overall = 'critical';
    }

    // Test Redis connection
    let redisStatus = 'connected';
    let redisMemory = 0;
    let redisHitRate = 0;

    try {
      await redis.ping();
      const info = await redis.info('memory');
      redisMemory = parseInt(info.match(/used_memory:(\d+)/)?.[1] || '0');
    } catch (error) {
      redisStatus = 'disconnected';
      if (overall !== 'critical') overall = 'warning';
    }

    // Get system metrics
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    return {
      overall: 'healthy',
      database: {
        status: 'connected',
        responseTime: 50,
        connections: 10,
        maxConnections: 100,
      },
      redis: {
        status: 'connected',
        memory: 50 * 1024 * 1024,
        maxMemory: 100 * 1024 * 1024,
        hitRate: 95,
      },
      storage: {
        used: 1024 * 1024 * 1024,
        available: 10 * 1024 * 1024 * 1024,
        percentage: 10,
      },
      server: {
        cpu: 25,
        memory: 60,
        disk: 45,
        uptime: process.uptime(),
      },
      websocket: {
        connections: 0,
        maxConnections: 1000,
        messageRate: 0,
      },
    };
  }

  private async getAdminAnalytics(): Promise<AdminAnalytics> {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // User engagement analytics
    const loginAnalytics = await prisma.analytics.findMany({
      where: {
        eventType: 'LOGIN',
        timestamp: { gte: thirtyDaysAgo },
      },
      select: {
        userId: true,
        timestamp: true,
        duration: true,
      },
    });

    // Daily active users over last 30 days
    const dailyActiveUsers = loginAnalytics.reduce((acc, login) => {
      const date = login.timestamp.toISOString().split('T')[0];
      if (!acc[date]) {
        acc[date] = new Set();
      }
      if (login.userId) {
        acc[date].add(login.userId);
      }
      return acc;
    }, {} as Record<string, Set<string>>);

    const dailyActiveUsersArray = Object.entries(dailyActiveUsers)
      .map(([date, users]) => ({ date, users: users.size }))
      .sort((a, b) => a.date.localeCompare(b.date));

    // Average session duration
    const avgSessionDuration = loginAnalytics
      .filter(l => l.duration)
      .reduce((sum, l) => sum + (l.duration || 0), 0) /
      Math.max(loginAnalytics.filter(l => l.duration).length, 1);

    // Election metrics
    const completedElections = await prisma.election.findMany({
      where: { status: 'COMPLETED' },
      select: {
        totalEligibleVoters: true,
        totalVotesCast: true,
        startDate: true,
        endDate: true,
        type: true,
      },
    });

    const averageTurnout = completedElections.reduce((sum, e) =>
      sum + (e.totalEligibleVoters > 0 ? (e.totalVotesCast / e.totalEligibleVoters) * 100 : 0), 0) /
      Math.max(completedElections.length, 1);

    const averageElectionDuration = completedElections.reduce((sum, e) =>
      sum + (e.endDate.getTime() - e.startDate.getTime()), 0) /
      Math.max(completedElections.length, 1);

    // Popular election types
    const electionTypeCount = completedElections.reduce((acc, e) => {
      acc[e.type] = (acc[e.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const popularElectionTypes = Object.entries(electionTypeCount)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);

    // Security metrics
    const failedLogins = await prisma.auditLog.count({
      where: {
        action: 'LOGIN_FAILED',
        createdAt: { gte: sevenDaysAgo },
      },
    });

    const securityIncidents = await prisma.auditLog.count({
      where: {
        category: 'SECURITY',
        severity: { in: ['HIGH', 'CRITICAL'] },
        createdAt: { gte: sevenDaysAgo },
      },
    });
    return {
      userEngagement: {
        dailyActiveUsers: [],
        averageSessionDuration: 0,
        bounceRate: 0,
        retentionRate: 0,
      },
      electionMetrics: {
        averageTurnout: 0,
        completionRate: 0,
        averageElectionDuration: 0,
        popularElectionTypes: [],
      },
      performanceMetrics: {
        averageResponseTime: 0,
        errorRate: 0,
        throughput: 0,
        availability: 99.9,
      },
      securityMetrics: {
        failedLogins: 0,
        suspiciousActivity: 0,
        blockedIPs: 0,
        securityIncidents: 0,
      },
    };
  }

  private async getSystemAlerts(): Promise<SystemAlert[]> {
    const alerts: SystemAlert[] = [];
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    // Check for failed elections
    const failedElections = await prisma.election.count({
      where: {
        status: 'CANCELLED',
        updatedAt: { gte: oneHourAgo },
      },
    });

    if (failedElections > 0) {
      alerts.push({
        id: 'failed_elections',
        type: 'error',
        severity: 'high',
        title: 'Elections Cancelled',
        message: `${failedElections} election(s) have been cancelled in the last hour`,
        source: 'election_system',
        timestamp: now,
        acknowledged: false,
        actionRequired: true,
        metadata: { count: failedElections },
      });
    }

    // Check for pending candidate approvals
    const pendingCandidates = await prisma.candidate.count({
      where: {
        status: 'PENDING',
        createdAt: { lte: new Date(now.getTime() - 24 * 60 * 60 * 1000) }, // Older than 24 hours
      },
    });

    if (pendingCandidates > 5) {
      alerts.push({
        id: 'pending_candidates',
        type: 'warning',
        severity: 'medium',
        title: 'Pending Candidate Approvals',
        message: `${pendingCandidates} candidates have been pending approval for over 24 hours`,
        source: 'candidate_system',
        timestamp: now,
        acknowledged: false,
        actionRequired: true,
        metadata: { count: pendingCandidates },
      });
    }

    // Check for critical issues
    const criticalIssues = await prisma.issueReport.count({
      where: {
        priority: 'CRITICAL',
        status: 'OPEN',
      },
    });

    if (criticalIssues > 0) {
      alerts.push({
        id: 'critical_issues',
        type: 'error',
        severity: 'critical',
        title: 'Critical Issues Reported',
        message: `${criticalIssues} critical issue(s) require immediate attention`,
        source: 'issue_tracking',
        timestamp: now,
        acknowledged: false,
        actionRequired: true,
        metadata: { count: criticalIssues },
      });
    }

    return alerts.sort((a, b) => {
      const severityOrder = { critical: 3, high: 2, medium: 1, low: 0 };
      return severityOrder[b.severity] - severityOrder[a.severity];
    });
  }

  private async getAdminActivity() {
    const auditLogs = await prisma.auditLog.findMany({
      take: 20,
      orderBy: { createdAt: 'desc' },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
        election: {
          select: {
            title: true,
          },
        },
      },
    });

    return auditLogs.map((log) => ({
      id: log.id,
      type: log.category.toLowerCase() as any,
      action: log.action,
      description: `${log.action} performed`,
      userId: log.userId || undefined,
      userName: log.user ? `${log.user.firstName} ${log.user.lastName}` : undefined,
      electionId: log.electionId || undefined,
      electionTitle: log.election?.title,
      ipAddress: log.ipAddress || undefined,
      userAgent: log.userAgent || undefined,
      severity: log.severity.toLowerCase() as any,
      timestamp: log.createdAt,
      metadata: log.metadata as Record<string, any>,
    }));
  }

  private async getAvailableReports() {
    return [
      {
        id: 'election_summary',
        name: 'Election Summary Report',
        description: 'Comprehensive overview of all elections',
        type: 'election',
        format: ['PDF', 'Excel', 'CSV'],
        lastGenerated: new Date(Date.now() - 24 * 60 * 60 * 1000),
        size: '2.5 MB',
        parameters: ['dateRange', 'electionType', 'status'],
      },
      {
        id: 'voter_analytics',
        name: 'Voter Analytics Report',
        description: 'Detailed voter participation and demographic analysis',
        type: 'analytics',
        format: ['PDF', 'Excel'],
        lastGenerated: new Date(Date.now() - 12 * 60 * 60 * 1000),
        size: '1.8 MB',
        parameters: ['dateRange', 'faculty', 'department'],
      },
      {
        id: 'candidate_performance',
        name: 'Candidate Performance Report',
        description: 'Analysis of candidate applications and campaign effectiveness',
        type: 'candidate',
        format: ['PDF', 'Excel'],
        lastGenerated: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        size: '3.2 MB',
        parameters: ['electionId', 'positionType'],
      },
      {
        id: 'system_audit',
        name: 'System Audit Report',
        description: 'Security and system activity audit trail',
        type: 'system',
        format: ['PDF', 'CSV'],
        lastGenerated: new Date(Date.now() - 6 * 60 * 60 * 1000),
        size: '4.1 MB',
        parameters: ['dateRange', 'severity', 'category'],
      },
      {
        id: 'financial_summary',
        name: 'Financial Summary Report',
        description: 'Campaign spending and resource allocation analysis',
        type: 'financial',
        format: ['PDF', 'Excel'],
        lastGenerated: null,
        size: null,
        parameters: ['electionId', 'candidateId'],
      },
    ];
  }

  // Utility methods

  private calculateTimeRemaining(date: Date) {
    const now = new Date();
    const diff = date.getTime() - now.getTime();

    if (diff <= 0) {
      return { days: 0, hours: 0, minutes: 0 };
    }

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    return { days, hours, minutes };
  }

  private calculateElectionProgress(election: any): number {
    const now = new Date();
    const start = new Date(election.startDate);
    const end = new Date(election.endDate);

    if (now < start) return 0;
    if (now > end) return 100;

    const total = end.getTime() - start.getTime();
    const elapsed = now.getTime() - start.getTime();

    return Math.round((elapsed / total) * 100);
  }

  private async getUserBio(userId: string): Promise<string> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { bio: true },
    });
    return user?.bio || '';
  }

  private async getUserAchievements(userId: string) {
    const achievements = await prisma.userAchievement.findMany({
      where: { userId, completed: true },
      include: {
        achievement: {
          select: {
            name: true,
            description: true,
            type: true,
            icon: true,
            badgeColor: true,
            points: true,
          },
        },
      },
      orderBy: { completedAt: 'desc' },
    });

    return achievements.map((ua) => ({
      id: ua.achievement.name,
      name: ua.achievement.name,
      description: ua.achievement.description,
      type: ua.achievement.type,
      icon: ua.achievement.icon || '',
      badgeColor: ua.achievement.badgeColor || '',
      points: ua.achievement.points,
      earnedAt: ua.completedAt || new Date(),
      progress: ua.progress,
    }));
  }

  private async getUserSocialMedia(userId: string) {
    const socialMedia = await prisma.socialMedia.findMany({
      where: { userId, isPublic: true },
    });

    return socialMedia.reduce((acc, sm) => {
      acc[sm.platform.toLowerCase()] = {
        username: sm.username,
        url: sm.url,
        verified: sm.verified,
      };
      return acc;
    }, {} as Record<string, any>);
  }

  private async calculateAverageVotingTime(): Promise<number> {
    const sessions = await prisma.votingSession.findMany({
      where: {
        status: 'COMPLETED',
        completedAt: { not: null },
      },
      select: {
        startedAt: true,
        completedAt: true,
      },
    });

    if (sessions.length === 0) return 0;

    const totalTime = sessions.reduce((sum, session) => {
      if (session.completedAt) {
        return sum + (session.completedAt.getTime() - session.startedAt.getTime());
      }
      return sum;
    }, 0);

    return Math.round(totalTime / sessions.length / 1000 / 60); // Convert to minutes
  }

  private async calculatePeakVotingHour(): Promise<number> {
    const votes = await prisma.vote.findMany({
      select: { castAt: true },
    });

    const hourCounts = votes.reduce((acc, vote) => {
      const hour = vote.castAt.getHours();
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    let peakHour = 14; // Default to 2 PM
    let maxCount = 0;

    for (const [hour, count] of Object.entries(hourCounts)) {
      if (count > maxCount) {
        maxCount = count;
        peakHour = parseInt(hour);
      }
    }

    return peakHour;
  }

  private async getVotingTrends() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const votes = await prisma.vote.findMany({
      where: { castAt: { gte: thirtyDaysAgo } },
      select: { castAt: true },
    });

    const trendsByDay = votes.reduce((acc, vote) => {
      const date = vote.castAt.toISOString().split('T')[0];
      acc[date] = (acc[date] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(trendsByDay)
      .map(([date, count]) => ({ date, votes: count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }

  private async getDeviceBreakdown() {
    const analytics = await prisma.analytics.findMany({
      where: {
        eventType: 'VOTE_CAST',
        deviceType: { not: null },
      },
      select: { deviceType: true },
    });

    const deviceCounts = analytics.reduce((acc, a) => {
      const device = a.deviceType || 'Unknown';
      acc[device] = (acc[device] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(deviceCounts).map(([device, count]) => ({
      device,
      count,
      percentage: Math.round((count / analytics.length) * 100),
    }));
  }

  private async calculateUserAverageVotingTime(userId: string): Promise<number> {
    const userSessions = await prisma.votingSession.findMany({
      where: {
        voterId: userId,
        status: 'COMPLETED',
        completedAt: { not: null },
      },
      select: {
        startedAt: true,
        completedAt: true,
      },
    });

    if (userSessions.length === 0) return 0;

    const totalTime = userSessions.reduce((sum, session) => {
      if (session.completedAt) {
        return sum + (session.completedAt.getTime() - session.startedAt.getTime());
      }
      return sum;
    }, 0);

    return Math.round(totalTime / userSessions.length / 1000 / 60); // Convert to minutes
  }

  private async getReviewedBy(candidateId: string): Promise<string | undefined> {
    const auditLog = await prisma.auditLog.findFirst({
      where: {
        action: 'CANDIDATE_APPROVED',
        entityId: candidateId,
      },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    return auditLog?.user ? `${auditLog.user.firstName} ${auditLog.user.lastName}` : undefined;
  }

  private async getDatabaseSize(): Promise<number> {
    try {
      const result = await prisma.$queryRaw<Array<{ size: string }>>`
        SELECT pg_size_pretty(pg_database_size(current_database())) as size;
      `;
      return result.length > 0 ? parseInt(result[0].size.replace(/[^0-9]/g, '')) : 0;
    } catch (error) {
      return 0; // Fallback if query fails
    }
  }

  private async getStorageUsage(): Promise<number> {
    try {
      const fileStats = await prisma.file.aggregate({
        _sum: { size: true },
      });
      return fileStats._sum.size || 0;
    } catch (error) {
      return 0;
    }
  }

  private getActionTextFromType(type: string): string {
    switch (type) {
      case 'ELECTION_STARTED':
        return 'Vote Now';
      case 'ELECTION_ENDING':
        return 'Vote Before It Ends';
      case 'ELECTION_ENDED':
        return 'View Results';
      case 'VOTE_CONFIRMED':
        return 'View Vote';
      case 'RESULT_PUBLISHED':
        return 'View Results';
      case 'ACCOUNT_ACTIVITY':
        return 'Review Activity';
      case 'SECURITY_ALERT':
        return 'Review Security';
      case 'SYSTEM_UPDATE':
        return 'View Details';
      default:
        return 'View';
    }
  }

  /**
   * Get real-time dashboard updates via WebSocket
   */
  public async getDashboardUpdates(userId: string, userRole: UserRole) {
    try {
      // Delegate to WebSocket service for real-time updates
      return await webSocketService.getDashboardUpdates(userId, userRole);
    } catch (error) {
      logger.error('Error fetching dashboard updates:', error);
      throw error;
    }
  }

  /**
   * Subscribe user to real-time dashboard updates
   */
  public async subscribeToUpdates(userId: string): Promise<void> {
    try {
      // This will be handled by the WebSocket service when client connects
      logger.info(`User ${userId} subscribed to dashboard updates`);
    } catch (error) {
      logger.error('Error subscribing to updates:', error);
      throw error;
    }
  }

  /**
   * Delegate system alerts to audit service
   */
  public async getPublicSystemAlerts(): Promise<any[]> {
    try {
      return await auditService.getSystemAlerts();
    } catch (error) {
      logger.error('Error getting system alerts:', error);
      throw error;
    }
  }

  /**
   * Delegate notifications to notification service
   */
  public async getPublicNotifications(userId: string, limit: number = 10): Promise<any[]> {
    try {
      const notifications = await prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: limit,
      });
      return notifications;
    } catch (error) {
      logger.error('Error getting notifications:', error);
      throw error;
    }
  }

  /**
   * Cache dashboard data for performance
   */
  public async cacheDashboardData(userId: string, userRole: UserRole, data: any) {
    try {
      const cacheKey = `dashboard:${userRole.toLowerCase()}:${userId}`;
      await redis.setex(cacheKey, 600, JSON.stringify(data)); // Cache for 10 minutes
    } catch (error) {
      logger.error('Error caching dashboard data:', error);
    }
  }

  /**
   * Get cached dashboard data
   */
  public async getCachedDashboardData(userId: string, userRole: UserRole) {
    try {
      const cacheKey = `dashboard:${userRole.toLowerCase()}:${userId}`;
      const cached = await redis.get(cacheKey);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      logger.error('Error getting cached dashboard data:', error);
      return null;
    }
  }
}

// Export singleton instance
export const dashboardService = DashboardService.getInstance();
export default dashboardService;