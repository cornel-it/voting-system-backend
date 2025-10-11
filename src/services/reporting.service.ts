import { PrismaClient, Election, ElectionStatus, ElectionType, UserRole } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger } from '../utils/logger';
import { AppError } from '../utils/errors';
import { encryptionService } from '../utils/encryption';
import PDFDocument from 'pdfkit';
import * as XLSX from 'xlsx';
import * as fs from 'fs/promises';
import * as path from 'path';
import { format } from 'date-fns';

export interface ReportFilters {
  startDate?: Date;
  endDate?: Date;
  electionId?: string;
  electionType?: ElectionType;
  faculty?: string;
  department?: string;
  yearOfStudy?: number;
  status?: ElectionStatus;
  userId?: string;
  includeArchived?: boolean;
}

export interface ElectionReport {
  election: {
    id: string;
    title: string;
    description: string;
    type: ElectionType;
    status: ElectionStatus;
    startDate: Date;
    endDate: Date;
    totalEligibleVoters: number;
    totalVotesCast: number;
    turnoutPercentage: number;
    createdBy: string;
    createdAt: Date;
  };
  positions: Array<{
    id: string;
    name: string;
    description: string;
    maxWinners: number;
    totalCandidates: number;
    totalVotes: number;
    candidates: Array<{
      id: string;
      firstName: string;
      lastName: string;
      studentId: string;
      faculty: string;
      department: string;
      course: string;
      yearOfStudy: number;
      totalVotes: number;
      votePercentage: number;
      rank: number;
      isWinner: boolean;
      manifesto?: string;
      photo?: string;
    }>;
  }>;
  demographics: {
    byFaculty: Array<{ faculty: string; voters: number; percentage: number }>;
    byDepartment: Array<{ department: string; voters: number; percentage: number }>;
    byYear: Array<{ year: number; voters: number; percentage: number }>;
    byGender: Array<{ gender: string; voters: number; percentage: number }>;
  };
  timeline: Array<{
    timestamp: Date;
    event: string;
    description: string;
    count: number;
  }>;
  statistics: {
    peakVotingHour: number;
    averageVotingTime: number;
    completionRate: number;
    invalidVotes: number;
    verifiedVotes: number;
    deviceBreakdown: Array<{ device: string; count: number; percentage: number }>;
  };
  integrity: {
    auditScore: number;
    securityEvents: number;
    anomalies: Array<{
      type: string;
      description: string;
      severity: string;
      timestamp: Date;
    }>;
  };
}

export interface SystemReport {
  period: { start: Date; end: Date };
  overview: {
    totalUsers: number;
    activeUsers: number;
    totalElections: number;
    completedElections: number;
    totalVotes: number;
    systemUptime: number;
  };
  userMetrics: {
    newRegistrations: number;
    verifiedUsers: number;
    usersByRole: Array<{ role: UserRole; count: number }>;
    usersByFaculty: Array<{ faculty: string; count: number }>;
    mostActiveUsers: Array<{
      userId: string;
      userName: string;
      actionCount: number;
      lastActivity: Date;
    }>;
  };
  electionMetrics: {
    electionsByType: Array<{ type: ElectionType; count: number }>;
    averageTurnout: number;
    totalCandidates: number;
    popularPositions: Array<{ position: string; candidateCount: number }>;
  };
  performanceMetrics: {
    averageResponseTime: number;
    errorRate: number;
    throughput: number;
    availability: number;
  };
  securityMetrics: {
    auditLogs: number;
    securityEvents: number;
    failedLogins: number;
    suspiciousActivity: number;
    blockedIPs: string[];
  };
}

export interface CandidateReport {
  candidate: {
    id: string;
    firstName: string;
    lastName: string;
    studentId: string;
    email: string;
    faculty: string;
    department: string;
    course: string;
    yearOfStudy: number;
    admissionYear: number;
  };
  applications: Array<{
    electionId: string;
    electionTitle: string;
    positionName: string;
    status: string;
    appliedAt: Date;
    approvedAt?: Date;
    rejectedAt?: Date;
    feedback?: string;
  }>;
  performance: Array<{
    electionId: string;
    electionTitle: string;
    positionName: string;
    totalVotes: number;
    votePercentage: number;
    rank: number;
    isWinner: boolean;
    demographics: {
      byFaculty: Array<{ faculty: string; votes: number }>;
      byYear: Array<{ year: number; votes: number }>;
    };
  }>;
  analytics: {
    totalElections: number;
    totalVotes: number;
    winRate: number;
    averageRank: number;
    strongestDemographic: string;
  };
}

export interface VoterReport {
  voter: {
    id: string;
    firstName: string;
    lastName: string;
    studentId: string;
    faculty: string;
    department: string;
    course: string;
    yearOfStudy: number;
  };
  votingHistory: Array<{
    electionId: string;
    electionTitle: string;
    electionType: ElectionType;
    votedAt: Date;
    positionsVoted: number;
    totalPositions: number;
    verificationCode: string;
  }>;
  statistics: {
    totalElectionsParticipated: number;
    participationRate: number;
    averageVotingTime: number;
    lastVoteDate?: Date;
    favoriteElectionType: ElectionType;
  };
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: 'election' | 'system' | 'candidate' | 'voter' | 'audit' | 'compliance';
  template: any;
  filters: ReportFilters;
  schedule?: {
    frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
    recipients: string[];
    format: 'pdf' | 'excel' | 'json';
  };
}

export class ReportingService {
  private static readonly CACHE_TTL = 3600; // 1 hour
  private static readonly REPORTS_DIR = path.join(__dirname, '../../reports');

  /**
   * Generate comprehensive election report
   */
  public static async generateElectionReport(
    electionId: string,
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | ElectionReport> {
    try {
      const cacheKey = `election-report:${electionId}:${format}`;
      const cached = await redis.get(cacheKey);

      if (cached && format === 'json') {
        return JSON.parse(cached);
      }

      // Get election data
      const election = await prisma.election.findUnique({
        where: { id: electionId },
        include: {
          positions: {
            include: {
              candidates: {
                include: {
                  results: true,
                },
              },
            },
          },
          votes: {
            include: {
              voter: {
                select: {
                  faculty: true,
                  department: true,
                  yearOfStudy: true,
                  gender: true,
                },
              },
            },
          },
          createdBy: {
            select: {
              firstName: true,
              lastName: true,
            },
          },
        },
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      // Build comprehensive report data
      const reportData = await this.buildElectionReportData(election);

      if (format === 'json') {
        await redis.setex(cacheKey, ReportingService.CACHE_TTL, JSON.stringify(reportData));
        return reportData;
      }

      if (format === 'excel') {
        return await this.generateElectionExcelReport(reportData);
      }

      // Generate PDF report
      return await this.generateElectionPDFReport(reportData);
    } catch (error) {
      logger.error('Error generating election report:', error);
      throw new AppError('Failed to generate election report', 500);
    }
  }

  /**
   * Generate system-wide report
   */
  public static async generateSystemReport(
    filters: ReportFilters = {},
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | SystemReport> {
    try {
      const startDate = filters.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const endDate = filters.endDate || new Date();

      const reportData = await this.buildSystemReportData(startDate, endDate, filters);

      if (format === 'json') {
        return reportData;
      }

      if (format === 'excel') {
        return await this.generateSystemExcelReport(reportData);
      }

      return await this.generateSystemPDFReport(reportData);
    } catch (error) {
      logger.error('Error generating system report:', error);
      throw new AppError('Failed to generate system report', 500);
    }
  }

  /**
   * Generate candidate performance report
   */
  public static async generateCandidateReport(
    candidateId: string,
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | CandidateReport> {
    try {
      const candidate = await prisma.candidate.findUnique({
        where: { id: candidateId },
        include: {
          election: true,
          position: true,
          results: true,
        },
      });

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      const reportData = await this.buildCandidateReportData(candidate);

      if (format === 'json') {
        return reportData;
      }

      if (format === 'excel') {
        return await this.generateCandidateExcelReport(reportData);
      }

      return await this.generateCandidatePDFReport(reportData);
    } catch (error) {
      logger.error('Error generating candidate report:', error);
      throw new AppError('Failed to generate candidate report', 500);
    }
  }

  /**
   * Generate voter participation report
   */
  public static async generateVoterReport(
    voterId: string,
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | VoterReport> {
    try {
      const voter = await prisma.user.findUnique({
        where: { id: voterId },
        include: {
          votes: {
            include: {
              election: true,
              position: true,
            },
          },
        },
      });

      if (!voter) {
        throw new AppError('Voter not found', 404);
      }

      const reportData = await this.buildVoterReportData(voter);

      if (format === 'json') {
        return reportData;
      }

      if (format === 'excel') {
        return await this.generateVoterExcelReport(reportData);
      }

      return await this.generateVoterPDFReport(reportData);
    } catch (error) {
      logger.error('Error generating voter report:', error);
      throw new AppError('Failed to generate voter report', 500);
    }
  }

  /**
   * Generate audit compliance report
   */
  public static async generateAuditReport(
    startDate: Date,
    endDate: Date,
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | any> {
    try {
      const auditLogs = await prisma.auditLog.findMany({
        where: {
          createdAt: {
            gte: startDate,
            lte: endDate,
          },
        },
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              role: true,
            },
          },
          election: {
            select: {
              title: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      const reportData = await this.buildAuditReportData(auditLogs, startDate, endDate);

      if (format === 'json') {
        return reportData;
      }

      if (format === 'excel') {
        return await this.generateAuditExcelReport(reportData);
      }

      return await this.generateAuditPDFReport(reportData);
    } catch (error) {
      logger.error('Error generating audit report:', error);
      throw new AppError('Failed to generate audit report', 500);
    }
  }

  /**
   * Generate comparative analysis report
   */
  public static async generateComparativeReport(
    electionIds: string[],
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<Buffer | any> {
    try {
      const elections = await Promise.all(
        electionIds.map(id => this.generateElectionReport(id, 'json'))
      );

      const comparativeData = this.buildComparativeAnalysis(elections as ElectionReport[]);

      if (format === 'json') {
        return comparativeData;
      }

      if (format === 'excel') {
        return await this.generateComparativeExcelReport(comparativeData);
      }

      return await this.generateComparativePDFReport(comparativeData);
    } catch (error) {
      logger.error('Error generating comparative report:', error);
      throw new AppError('Failed to generate comparative report', 500);
    }
  }

  /**
   * Schedule automated reports
   */
  public static async scheduleReport(template: ReportTemplate): Promise<string> {
    try {
      // Store report template
      const templateId = encryptionService.generateToken(12);
      await redis.setex(
        `report-template:${templateId}`,
        86400 * 7, // 7 days
        JSON.stringify(template)
      );

      // In a real implementation, you would integrate with a job scheduler
      // like Bull, Agenda, or node-cron
      logger.info('Report scheduled', {
        templateId,
        type: template.type,
        frequency: template.schedule?.frequency,
      });

      return templateId;
    } catch (error) {
      logger.error('Error scheduling report:', error);
      throw new AppError('Failed to schedule report', 500);
    }
  }

  /**
   * Get available report templates
   */
  public static async getReportTemplates(): Promise<ReportTemplate[]> {
    try {
      // Default templates
      return [
        {
          id: 'election-summary',
          name: 'Election Summary Report',
          description: 'Comprehensive election results and analytics',
          type: 'election',
          template: {},
          filters: {},
        },
        {
          id: 'system-overview',
          name: 'System Overview Report',
          description: 'System-wide statistics and performance metrics',
          type: 'system',
          template: {},
          filters: {},
        },
        {
          id: 'audit-compliance',
          name: 'Audit & Compliance Report',
          description: 'Security audit logs and compliance metrics',
          type: 'audit',
          template: {},
          filters: {},
        },
        {
          id: 'voter-participation',
          name: 'Voter Participation Analysis',
          description: 'Detailed voter engagement and participation patterns',
          type: 'voter',
          template: {},
          filters: {},
        },
        {
          id: 'candidate-performance',
          name: 'Candidate Performance Report',
          description: 'Individual candidate statistics and performance metrics',
          type: 'candidate',
          template: {},
          filters: {},
        },
      ];
    } catch (error) {
      logger.error('Error fetching report templates:', error);
      throw new AppError('Failed to fetch report templates', 500);
    }
  }

  // Private helper methods for building report data

  private static async buildElectionReportData(election: any): Promise<ElectionReport> {
    // Build positions data
    const positions = election.positions.map((position: any) => ({
      id: position.id,
      name: position.name,
      description: position.description,
      maxWinners: position.maxWinners,
      totalCandidates: position.candidates.length,
      totalVotes: position.candidates.reduce((sum: number, c: any) =>
        sum + (c.results[0]?.totalVotes || 0), 0),
      candidates: position.candidates.map((candidate: any) => ({
        id: candidate.id,
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        studentId: candidate.studentId,
        faculty: candidate.faculty,
        department: candidate.department,
        course: candidate.course,
        yearOfStudy: candidate.yearOfStudy,
        totalVotes: candidate.results[0]?.totalVotes || 0,
        votePercentage: candidate.results[0]?.percentage || 0,
        rank: candidate.results[0]?.rank || 0,
        isWinner: candidate.results[0]?.isWinner || false,
        manifesto: candidate.manifesto,
        photo: candidate.photo,
      })).sort((a: any, b: any) => b.totalVotes - a.totalVotes),
    }));

    // Build demographics
    const demographics = await this.calculateElectionDemographics(election);

    // Build timeline
    const timeline = await this.buildElectionTimeline(election.id);

    // Build statistics
    const statistics = await this.calculateElectionStatistics(election);

    // Build integrity metrics
    const integrity = await this.calculateElectionIntegrity(election.id);

    return {
      election: {
        id: election.id,
        title: election.title,
        description: election.description,
        type: election.type,
        status: election.status,
        startDate: election.startDate,
        endDate: election.endDate,
        totalEligibleVoters: election.totalEligibleVoters,
        totalVotesCast: election.totalVotesCast,
        turnoutPercentage: election.turnoutPercentage,
        createdBy: `${election.createdBy.firstName} ${election.createdBy.lastName}`,
        createdAt: election.createdAt,
      },
      positions,
      demographics,
      timeline,
      statistics,
      integrity,
    };
  }

  private static async buildSystemReportData(
    startDate: Date,
    endDate: Date,
    filters: ReportFilters
  ): Promise<SystemReport> {
    const [overview, userMetrics, electionMetrics, performanceMetrics, securityMetrics] = await Promise.all([
      this.getSystemOverview(startDate, endDate),
      this.getUserMetrics(startDate, endDate),
      this.getElectionMetrics(startDate, endDate),
      this.getPerformanceMetrics(startDate, endDate),
      this.getSecurityMetrics(startDate, endDate),
    ]);

    return {
      period: { start: startDate, end: endDate },
      overview,
      userMetrics,
      electionMetrics,
      performanceMetrics,
      securityMetrics,
    };
  }

  private static async buildCandidateReportData(candidate: any): Promise<CandidateReport> {
    const applications = [{
      electionId: candidate.electionId,
      electionTitle: candidate.election.title,
      positionName: candidate.position.name,
      status: candidate.status,
      appliedAt: candidate.createdAt,
      approvedAt: candidate.verifiedAt,
      rejectedAt: candidate.status === 'REJECTED' ? candidate.updatedAt : undefined,
      feedback: candidate.disqualificationReason,
    }];

    const performance = await Promise.all(
      (candidate.results && candidate.results.length > 0 ? [candidate] : [])
        .map(async (app: any) => {
          const demographics = await this.getCandidateDemographics(app.id);
          return {
            electionId: app.electionId,
            electionTitle: app.election.title,
            positionName: app.position.name,
            totalVotes: app.results[0].totalVotes,
            votePercentage: app.results[0].percentage,
            rank: app.results[0].rank,
            isWinner: app.results[0].isWinner,
            demographics,
          };
        })
    );

    const analytics = this.calculateCandidateAnalytics(performance);

    return {
      candidate: {
        id: candidate.id,
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        studentId: candidate.studentId,
        email: candidate.email,
        faculty: candidate.faculty,
        department: candidate.department,
        course: candidate.course,
        yearOfStudy: candidate.yearOfStudy,
        admissionYear: candidate.admissionYear,
      },
      applications,
      performance,
      analytics,
    };
  }

  private static async buildVoterReportData(voter: any): Promise<VoterReport> {
    const votingHistory = voter.votes.map((vote: any) => ({
      electionId: vote.electionId,
      electionTitle: vote.election.title,
      electionType: vote.election.type,
      votedAt: vote.castAt,
      positionsVoted: 1, // Each vote is for one position
      totalPositions: vote.election.positions?.length || 1,
      verificationCode: vote.verificationCode,
    }));

    const statistics = await this.calculateVoterStatistics(votingHistory, voter.id);

    return {
      voter: {
        id: voter.id,
        firstName: voter.firstName,
        lastName: voter.lastName,
        studentId: voter.studentId,
        faculty: voter.faculty,
        department: voter.department,
        course: voter.course,
        yearOfStudy: voter.yearOfStudy,
      },
      votingHistory,
      statistics,
    };
  }

  private static async buildAuditReportData(auditLogs: any[], startDate: Date, endDate: Date) {
    const summary = {
      totalLogs: auditLogs.length,
      criticalEvents: auditLogs.filter(log => log.severity === 'CRITICAL').length,
      securityEvents: auditLogs.filter(log => log.category === 'SECURITY').length,
      userActions: auditLogs.filter(log => log.userId).length,
      systemActions: auditLogs.filter(log => !log.userId).length,
    };

    const categorizedLogs = this.categorizeAuditLogs(auditLogs);
    const timelineAnalysis = this.analyzeAuditTimeline(auditLogs);
    const riskAssessment = this.assessAuditRisks(auditLogs);

    return {
      period: { start: startDate, end: endDate },
      summary,
      categorizedLogs,
      timelineAnalysis,
      riskAssessment,
      logs: auditLogs.map(log => ({
        id: log.id,
        action: log.action,
        category: log.category,
        severity: log.severity,
        user: log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System',
        timestamp: log.createdAt,
        metadata: log.metadata,
      })),
    };
  }

  // PDF Generation Methods

  private static async generateElectionPDFReport(data: ElectionReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Header
        doc.fontSize(20).text('JKUAT Voting System - Election Report', { align: 'center' });
        doc.fontSize(16).text(data.election.title, { align: 'center' });
        doc.moveDown();

        // Election Info
        doc.fontSize(12);
        doc.text(`Election Type: ${data.election.type}`);
        doc.text(`Status: ${data.election.status}`);
        doc.text(`Period: ${format(data.election.startDate, 'PPP')} - ${format(data.election.endDate, 'PPP')}`);
        doc.text(`Total Eligible Voters: ${data.election.totalEligibleVoters.toLocaleString()}`);
        doc.text(`Total Votes Cast: ${data.election.totalVotesCast.toLocaleString()}`);
        doc.text(`Turnout: ${data.election.turnoutPercentage.toFixed(2)}%`);
        doc.moveDown();

        // Positions and Results
        doc.fontSize(14).text('Election Results', { underline: true });
        doc.moveDown();

        data.positions.forEach(position => {
          doc.fontSize(12).text(`Position: ${position.name}`, { underline: true });
          doc.text(`Total Candidates: ${position.totalCandidates}`);
          doc.text(`Total Votes: ${position.totalVotes.toLocaleString()}`);
          doc.moveDown(0.5);

          position.candidates.forEach((candidate, index) => {
            const winnerMark = candidate.isWinner ? ' 🏆' : '';
            doc.text(
              `${index + 1}. ${candidate.firstName} ${candidate.lastName}${winnerMark} - ${candidate.totalVotes.toLocaleString()} votes (${candidate.votePercentage.toFixed(2)}%)`
            );
          });
          doc.moveDown();
        });

        // Demographics
        doc.addPage();
        doc.fontSize(14).text('Voter Demographics', { underline: true });
        doc.moveDown();

        doc.fontSize(12).text('By Faculty:');
        data.demographics.byFaculty.forEach(item => {
          doc.text(`${item.faculty}: ${item.voters.toLocaleString()} (${item.percentage.toFixed(2)}%)`);
        });
        doc.moveDown();

        doc.text('By Year of Study:');
        data.demographics.byYear.forEach(item => {
          doc.text(`Year ${item.year}: ${item.voters.toLocaleString()} (${item.percentage.toFixed(2)}%)`);
        });

        // Statistics
        doc.moveDown();
        doc.fontSize(14).text('Statistics', { underline: true });
        doc.fontSize(12);
        doc.text(`Peak Voting Hour: ${data.statistics.peakVotingHour}:00`);
        doc.text(`Average Voting Time: ${data.statistics.averageVotingTime} minutes`);
        doc.text(`Completion Rate: ${data.statistics.completionRate.toFixed(2)}%`);
        doc.text(`Verified Votes: ${data.statistics.verifiedVotes.toLocaleString()}`);

        // Integrity
        doc.moveDown();
        doc.fontSize(14).text('Election Integrity', { underline: true });
        doc.fontSize(12);
        doc.text(`Audit Score: ${data.integrity.auditScore.toFixed(2)}%`);
        doc.text(`Security Events: ${data.integrity.securityEvents}`);

        // Footer
        doc.fontSize(8).text(`Generated on ${format(new Date(), 'PPPpp')}`, 0, doc.page.height - 50, {
          align: 'center',
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private static async generateSystemPDFReport(data: SystemReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Header
        doc.fontSize(20).text('JKUAT Voting System - System Report', { align: 'center' });
        doc.fontSize(14).text(`Period: ${format(data.period.start, 'PPP')} - ${format(data.period.end, 'PPP')}`, { align: 'center' });
        doc.moveDown();

        // System Overview
        doc.fontSize(14).text('System Overview', { underline: true });
        doc.fontSize(12);
        doc.text(`Total Users: ${data.overview.totalUsers.toLocaleString()}`);
        doc.text(`Active Users: ${data.overview.activeUsers.toLocaleString()}`);
        doc.text(`Total Elections: ${data.overview.totalElections.toLocaleString()}`);
        doc.text(`Completed Elections: ${data.overview.completedElections.toLocaleString()}`);
        doc.text(`Total Votes: ${data.overview.totalVotes.toLocaleString()}`);
        doc.text(`System Uptime: ${(data.overview.systemUptime / 3600).toFixed(2)} hours`);
        doc.moveDown();

        // User Metrics
        doc.fontSize(14).text('User Metrics', { underline: true });
        doc.fontSize(12);
        doc.text(`New Registrations: ${data.userMetrics.newRegistrations.toLocaleString()}`);
        doc.text(`Verified Users: ${data.userMetrics.verifiedUsers.toLocaleString()}`);
        doc.moveDown();

        doc.text('Users by Role:');
        data.userMetrics.usersByRole.forEach(item => {
          doc.text(`${item.role}: ${item.count.toLocaleString()}`);
        });
        doc.moveDown();

        // Performance Metrics
        doc.fontSize(14).text('Performance Metrics', { underline: true });
        doc.fontSize(12);
        doc.text(`Average Response Time: ${data.performanceMetrics.averageResponseTime}ms`);
        doc.text(`Error Rate: ${data.performanceMetrics.errorRate.toFixed(2)}%`);
        doc.text(`Throughput: ${data.performanceMetrics.throughput.toLocaleString()} req/min`);
        doc.text(`Availability: ${data.performanceMetrics.availability.toFixed(2)}%`);

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private static async generateCandidatePDFReport(data: CandidateReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Header
        doc.fontSize(20).text('JKUAT Voting System - Candidate Report', { align: 'center' });
        doc.fontSize(16).text(`${data.candidate.firstName} ${data.candidate.lastName}`, { align: 'center' });
        doc.moveDown();

        // Candidate Info
        doc.fontSize(12);
        doc.text(`Student ID: ${data.candidate.studentId}`);
        doc.text(`Email: ${data.candidate.email}`);
        doc.text(`Faculty: ${data.candidate.faculty}`);
        doc.text(`Department: ${data.candidate.department}`);
        doc.text(`Course: ${data.candidate.course}`);
        doc.text(`Year of Study: ${data.candidate.yearOfStudy}`);
        doc.moveDown();

        // Analytics
        doc.fontSize(14).text('Performance Analytics', { underline: true });
        doc.fontSize(12);
        doc.text(`Total Elections: ${data.analytics.totalElections}`);
        doc.text(`Total Votes Received: ${data.analytics.totalVotes.toLocaleString()}`);
        doc.text(`Win Rate: ${data.analytics.winRate.toFixed(2)}%`);
        doc.text(`Average Rank: ${data.analytics.averageRank.toFixed(2)}`);
        doc.moveDown();

        // Applications
        doc.fontSize(14).text('Applications History', { underline: true });
        data.applications.forEach(app => {
          doc.fontSize(11);
          doc.text(`${app.electionTitle} - ${app.positionName}`);
          doc.text(`Status: ${app.status}, Applied: ${format(app.appliedAt, 'PPP')}`);
          if (app.feedback) doc.text(`Feedback: ${app.feedback}`);
          doc.moveDown(0.5);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private static async generateVoterPDFReport(data: VoterReport): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        doc.fontSize(20).text('JKUAT Voting System - Voter Report', { align: 'center' });
        doc.fontSize(16).text(`${data.voter.firstName} ${data.voter.lastName}`, { align: 'center' });
        doc.moveDown();

        // Voter info and statistics
        doc.fontSize(12);
        doc.text(`Student ID: ${data.voter.studentId}`);
        doc.text(`Faculty: ${data.voter.faculty}`);
        doc.text(`Elections Participated: ${data.statistics.totalElectionsParticipated}`);
        doc.text(`Participation Rate: ${data.statistics.participationRate.toFixed(2)}%`);
        doc.moveDown();

        // Voting history
        doc.fontSize(14).text('Voting History', { underline: true });
        data.votingHistory.forEach(vote => {
          doc.fontSize(11);
          doc.text(`${vote.electionTitle} (${vote.electionType})`);
          doc.text(`Voted: ${format(vote.votedAt, 'PPPpp')}`);
          doc.text(`Verification: ${vote.verificationCode}`);
          doc.moveDown(0.5);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private static async generateAuditPDFReport(data: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        doc.fontSize(20).text('JKUAT Voting System - Audit Report', { align: 'center' });
        doc.fontSize(14).text(`Period: ${format(data.period.start, 'PPP')} - ${format(data.period.end, 'PPP')}`, { align: 'center' });
        doc.moveDown();

        // Summary
        doc.fontSize(14).text('Audit Summary', { underline: true });
        doc.fontSize(12);
        doc.text(`Total Logs: ${data.summary.totalLogs.toLocaleString()}`);
        doc.text(`Critical Events: ${data.summary.criticalEvents.toLocaleString()}`);
        doc.text(`Security Events: ${data.summary.securityEvents.toLocaleString()}`);
        doc.text(`User Actions: ${data.summary.userActions.toLocaleString()}`);
        doc.text(`System Actions: ${data.summary.systemActions.toLocaleString()}`);

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private static async generateComparativePDFReport(data: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();
        const chunks: Buffer[] = [];

        doc.on('data', (chunk: Buffer) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        doc.fontSize(20).text('JKUAT Voting System - Comparative Analysis', { align: 'center' });
        doc.moveDown();

        // Add comparative analysis content here
        doc.fontSize(12).text('Comparative analysis content would be generated here...');

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  // Excel Generation Methods

  private static async generateElectionExcelReport(data: ElectionReport): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // Overview sheet
    const overviewData = [
      ['Election Title', data.election.title],
      ['Type', data.election.type],
      ['Status', data.election.status],
      ['Start Date', format(data.election.startDate, 'PPP')],
      ['End Date', format(data.election.endDate, 'PPP')],
      ['Total Eligible Voters', data.election.totalEligibleVoters],
      ['Total Votes Cast', data.election.totalVotesCast],
      ['Turnout Percentage', `${data.election.turnoutPercentage.toFixed(2)}%`],
    ];
    const overviewSheet = XLSX.utils.aoa_to_sheet(overviewData);
    XLSX.utils.book_append_sheet(workbook, overviewSheet, 'Overview');

    // Results sheet
    const resultsData = [['Position', 'Candidate', 'Student ID', 'Faculty', 'Votes', 'Percentage', 'Winner']];
    data.positions.forEach(position => {
      position.candidates.forEach(candidate => {
        resultsData.push([
          position.name,
          `${candidate.firstName} ${candidate.lastName}`,
          candidate.studentId,
          candidate.faculty,
          candidate.totalVotes.toString(),
          `${candidate.votePercentage.toFixed(2)}%`,
          candidate.isWinner ? 'Yes' : 'No',
        ]);
      });
    });
    const resultsSheet = XLSX.utils.aoa_to_sheet(resultsData);
    XLSX.utils.book_append_sheet(workbook, resultsSheet, 'Results');

    // Demographics sheet
    const demographicsData = [['Category', 'Value', 'Count', 'Percentage']];
    data.demographics.byFaculty.forEach(item => {
      demographicsData.push(['Faculty', item.faculty, item.voters.toString(), `${item.percentage.toFixed(2)}%`]);
    });
    data.demographics.byYear.forEach(item => {
      demographicsData.push(['Year', item.year.toString(), item.voters.toString(), `${item.percentage.toFixed(2)}%`]);
    });
    const demographicsSheet = XLSX.utils.aoa_to_sheet(demographicsData);
    XLSX.utils.book_append_sheet(workbook, demographicsSheet, 'Demographics');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  private static async generateSystemExcelReport(data: SystemReport): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // System overview
    const overviewData = [
      ['Metric', 'Value'],
      ['Total Users', data.overview.totalUsers],
      ['Active Users', data.overview.activeUsers],
      ['Total Elections', data.overview.totalElections],
      ['Completed Elections', data.overview.completedElections],
      ['Total Votes', data.overview.totalVotes],
      ['System Uptime (hours)', (data.overview.systemUptime / 3600).toFixed(2)],
    ];
    const overviewSheet = XLSX.utils.aoa_to_sheet(overviewData);
    XLSX.utils.book_append_sheet(workbook, overviewSheet, 'Overview');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  private static async generateCandidateExcelReport(data: CandidateReport): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // Candidate info
    const infoData = [
      ['Field', 'Value'],
      ['Name', `${data.candidate.firstName} ${data.candidate.lastName}`],
      ['Student ID', data.candidate.studentId],
      ['Email', data.candidate.email],
      ['Faculty', data.candidate.faculty],
      ['Department', data.candidate.department],
      ['Course', data.candidate.course],
      ['Year of Study', data.candidate.yearOfStudy],
    ];
    const infoSheet = XLSX.utils.aoa_to_sheet(infoData);
    XLSX.utils.book_append_sheet(workbook, infoSheet, 'Info');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  private static async generateVoterExcelReport(data: VoterReport): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // Voter info and voting history
    const historyData = [['Election', 'Type', 'Voted At', 'Verification Code']];
    data.votingHistory.forEach(vote => {
      historyData.push([
        vote.electionTitle,
        vote.electionType,
        format(vote.votedAt, 'PPPpp'),
        vote.verificationCode,
      ]);
    });
    const historySheet = XLSX.utils.aoa_to_sheet(historyData);
    XLSX.utils.book_append_sheet(workbook, historySheet, 'Voting History');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  private static async generateAuditExcelReport(data: any): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // Audit logs
    const logsData = [['ID', 'Action', 'Category', 'Severity', 'User', 'Timestamp']];
    data.logs.forEach((log: any) => {
      logsData.push([
        log.id,
        log.action,
        log.category,
        log.severity,
        log.user,
        format(log.timestamp, 'PPPpp'),
      ]);
    });
    const logsSheet = XLSX.utils.aoa_to_sheet(logsData);
    XLSX.utils.book_append_sheet(workbook, logsSheet, 'Audit Logs');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  private static async generateComparativeExcelReport(data: any): Promise<Buffer> {
    const workbook = XLSX.utils.book_new();

    // Placeholder for comparative analysis
    const compData = [['Election', 'Turnout', 'Total Votes']];
    const compSheet = XLSX.utils.aoa_to_sheet(compData);
    XLSX.utils.book_append_sheet(workbook, compSheet, 'Comparison');

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
  }

  // Helper calculation methods

  private static async calculateElectionDemographics(election: any) {
    const voters = election.votes.map((vote: any) => vote.voter);
    const total = voters.length;

    // By faculty
    const byFaculty = voters.reduce((acc: any, voter: any) => {
      acc[voter.faculty] = (acc[voter.faculty] || 0) + 1;
      return acc;
    }, {});

    // By year
    const byYear = voters.reduce((acc: any, voter: any) => {
      acc[voter.yearOfStudy] = (acc[voter.yearOfStudy] || 0) + 1;
      return acc;
    }, {});

    // By gender
    const byGender = voters.reduce((acc: any, voter: any) => {
      const gender = voter.gender || 'Unknown';
      acc[gender] = (acc[gender] || 0) + 1;
      return acc;
    }, {});

    return {
      byFaculty: Object.entries(byFaculty).map(([faculty, count]: [string, any]) => ({
        faculty,
        voters: count,
        percentage: total > 0 ? (count / total) * 100 : 0,
      })),
      byDepartment: [], // TODO: Implement department breakdown
      byYear: Object.entries(byYear).map(([year, count]: [string, any]) => ({
        year: parseInt(year),
        voters: count,
        percentage: total > 0 ? (count / total) * 100 : 0,
      })),
      byGender: Object.entries(byGender).map(([gender, count]: [string, any]) => ({
        gender,
        voters: count,
        percentage: total > 0 ? (count / total) * 100 : 0,
      })),
    };
  }

  private static async buildElectionTimeline(electionId: string) {
    const events = await prisma.auditLog.findMany({
      where: { electionId },
      orderBy: { createdAt: 'asc' },
    });

    const timeline = events.reduce((acc: any[], event) => {
      const existing = acc.find(item =>
        item.event === event.action &&
        Math.abs(item.timestamp.getTime() - event.createdAt.getTime()) < 60000
      );

      if (existing) {
        existing.count++;
      } else {
        acc.push({
          timestamp: event.createdAt,
          event: event.action,
          description: `${event.action} occurred`,
          count: 1,
        });
      }

      return acc;
    }, []);

    return timeline;
  }

  private static async calculateElectionStatistics(election: any) {
    // Get all votes for this election
    const votes = await prisma.vote.findMany({
      where: { electionId: election.id },
      select: {
        castAt: true,
        verified: true,
        metadata: true,
      },
    });

    // Calculate peak voting hour
    const hourlyVotes = votes.reduce((acc, vote) => {
      const hour = vote.castAt.getHours();
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    const peakVotingHour = Object.entries(hourlyVotes).reduce(
      (max, [hour, count]) => count > max.count ? { hour: parseInt(hour), count } : max,
      { hour: 0, count: 0 }
    ).hour;

    // Calculate average voting time (from session start to vote cast)
    const votingTimes = votes
      .filter((vote: any) => vote.metadata && typeof vote.metadata === 'object' && 'sessionStart' in vote.metadata)
      .map((vote: any) => {
        const sessionStart = new Date((vote.metadata as any).sessionStart);
        const castTime = vote.castAt;
        return (castTime.getTime() - sessionStart.getTime()) / (1000 * 60); // minutes
      });

    const averageVotingTime = votingTimes.length > 0
      ? votingTimes.reduce((sum, time) => sum + time, 0) / votingTimes.length
      : 0;

    // Calculate completion rate (voters who started but didn't finish)
    const totalSessions = await prisma.auditLog.count({
      where: {
        electionId: election.id,
        action: 'VOTING_SESSION_STARTED',
      },
    });

    const completionRate = totalSessions > 0 ? (votes.length / totalSessions) * 100 : 100;

    // Count verified vs unverified votes
    const verifiedVotes = votes.filter(vote => vote.verified).length;
    const invalidVotes = votes.length - verifiedVotes;

    // Device breakdown from audit logs
    const deviceLogs = await prisma.auditLog.findMany({
      where: {
        electionId: election.id,
        action: 'VOTE_CAST',
        userAgent: { not: null },
      },
      select: { userAgent: true },
    });

    const deviceBreakdown = deviceLogs.reduce((acc, log) => {
      let device = 'Unknown';
      const userAgent = log.userAgent?.toLowerCase() || '';

      if (userAgent.includes('mobile') || userAgent.includes('android') || userAgent.includes('iphone')) {
        device = 'Mobile';
      } else if (userAgent.includes('tablet') || userAgent.includes('ipad')) {
        device = 'Tablet';
      } else if (userAgent.includes('mozilla') || userAgent.includes('chrome') || userAgent.includes('firefox')) {
        device = 'Desktop';
      }

      acc[device] = (acc[device] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const totalDevices = Object.values(deviceBreakdown).reduce((sum, count) => sum + count, 0);
    const deviceBreakdownArray = Object.entries(deviceBreakdown).map(([device, count]) => ({
      device,
      count,
      percentage: totalDevices > 0 ? (count / totalDevices) * 100 : 0,
    }));

    return {
      peakVotingHour,
      averageVotingTime: Math.round(averageVotingTime * 100) / 100,
      completionRate: Math.round(completionRate * 100) / 100,
      invalidVotes,
      verifiedVotes,
      deviceBreakdown: deviceBreakdownArray,
    };
  }

  private static async calculateElectionIntegrity(electionId: string) {
    const [auditLogs, securityEvents, anomalyLogs] = await Promise.all([
      prisma.auditLog.count({
        where: { electionId },
      }),
      prisma.auditLog.count({
        where: {
          electionId,
          severity: { in: ['HIGH', 'CRITICAL'] },
        },
      }),
      prisma.auditLog.findMany({
        where: {
          electionId,
          OR: [
            { action: { contains: 'SUSPICIOUS' } },
            { action: { contains: 'ANOMALY' } },
            { action: { contains: 'VIOLATION' } },
            { metadata: { path: ['flags'], not: { equals: [] } } },
          ],
        },
        select: {
          action: true,
          severity: true,
          createdAt: true,
          metadata: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 10,
      }),
    ]);

    // Calculate audit score based on multiple factors
    let auditScore = 100;

    // Deduct points for security events
    if (auditLogs > 0) {
      const securityEventRatio = securityEvents / auditLogs;
      auditScore -= securityEventRatio * 50; // Max 50 points deduction for security events
    }

    // Deduct points for anomalies
    const anomalyCount = anomalyLogs.length;
    auditScore -= Math.min(anomalyCount * 5, 30); // Max 30 points deduction for anomalies

    // Ensure score doesn't go below 0
    auditScore = Math.max(0, auditScore);

    // Map anomaly logs to proper format
    const anomalies = anomalyLogs.map(log => ({
      type: log.action,
      description: this.generateAnomalyDescription(log),
      severity: log.severity,
      timestamp: log.createdAt,
    }));

    return {
      auditScore: Math.round(auditScore * 100) / 100,
      securityEvents,
      anomalies,
    };
  }

  private static async getSystemOverview(startDate: Date, endDate: Date) {
    const [totalUsers, activeUsers, totalElections, completedElections, totalVotes] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { isActive: true } }),
      prisma.election.count(),
      prisma.election.count({ where: { status: 'COMPLETED' } }),
      prisma.vote.count(),
    ]);

    return {
      totalUsers,
      activeUsers,
      totalElections,
      completedElections,
      totalVotes,
      systemUptime: process.uptime(),
    };
  }

  private static async getUserMetrics(startDate: Date, endDate: Date) {
    const [newRegistrations, verifiedUsers, usersByRole, usersByFaculty, mostActiveUsersData] = await Promise.all([
      prisma.user.count({ where: { createdAt: { gte: startDate, lte: endDate } } }),
      prisma.user.count({ where: { isVerified: true } }),
      prisma.user.groupBy({ by: ['role'], _count: true }),
      prisma.user.groupBy({ by: ['faculty'], _count: true }),
      prisma.auditLog.groupBy({
        by: ['userId'],
        where: {
          createdAt: { gte: startDate, lte: endDate },
          userId: { not: null },
        },
        _count: true,
        _max: { createdAt: true },
        orderBy: { _count: { userId: 'desc' } },
        take: 10,
      }),
    ]);

    // Get user details for most active users
    const mostActiveUsers = await Promise.all(
      mostActiveUsersData.map(async (userData) => {
        const user = await prisma.user.findUnique({
          where: { id: userData.userId! },
          select: {
            id: true,
            firstName: true,
            lastName: true,
          },
        });

        return {
          userId: userData.userId!,
          userName: user ? `${user.firstName} ${user.lastName}` : 'Unknown User',
          actionCount: userData._count,
          lastActivity: userData._max.createdAt!,
        };
      })
    );

    return {
      newRegistrations,
      verifiedUsers,
      usersByRole: usersByRole.map(item => ({ role: item.role, count: item._count })),
      usersByFaculty: usersByFaculty.map(item => ({ faculty: item.faculty, count: item._count })),
      mostActiveUsers,
    };
  }

  private static async getElectionMetrics(startDate: Date, endDate: Date) {
    const [electionsByType, totalCandidates, elections, popularPositionsData] = await Promise.all([
      prisma.election.groupBy({
        by: ['type'],
        where: { createdAt: { gte: startDate, lte: endDate } },
        _count: true
      }),
      prisma.candidate.count({
        where: { createdAt: { gte: startDate, lte: endDate } }
      }),
      prisma.election.findMany({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          status: 'COMPLETED',
        },
        select: { turnoutPercentage: true }
      }),
      prisma.position.groupBy({
        by: ['name'],
        _count: { id: true },
        orderBy: { _count: { id: 'desc' } },
        take: 10
      })
    ]);

    // Calculate average turnout from completed elections
    const averageTurnout = elections.length > 0
      ? elections.reduce((sum, election) => sum + (election.turnoutPercentage || 0), 0) / elections.length
      : 0;

    // Map popular positions
    const popularPositions = popularPositionsData.map(pos => ({
      position: pos.name,
      candidateCount: pos._count.id
    }));

    return {
      electionsByType: electionsByType.map(item => ({ type: item.type, count: item._count })),
      averageTurnout: Math.round(averageTurnout * 100) / 100,
      totalCandidates,
      popularPositions,
    };
  }

  private static async getPerformanceMetrics(startDate: Date, endDate: Date) {
    // Get performance metrics from audit logs
    const [responseTimes, errorLogs, totalRequests, systemLogs] = await Promise.all([
      prisma.auditLog.findMany({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          metadata: { not: {} }
        },
        select: { metadata: true }
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          OR: [
            { severity: 'HIGH' },
            { severity: 'CRITICAL' },
            { action: { contains: 'ERROR' } },
            { action: { contains: 'FAILED' } }
          ]
        }
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          category: { in: ['USER', 'VOTING', 'ELECTION', 'SYSTEM'] }
        }
      }),
      prisma.auditLog.findMany({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          action: { in: ['SYSTEM_START', 'SYSTEM_RESTART', 'SYSTEM_ERROR'] }
        },
        select: { action: true, createdAt: true }
      })
    ]);

    // Calculate average response time
    const responseTimeValues = responseTimes
      .map(log => typeof log.metadata === 'object' && log.metadata !== null && 'responseTime' in log.metadata ? (log.metadata as any).responseTime as number : null)
      .filter((time): time is number => typeof time === 'number' && time > 0);

    const averageResponseTime = responseTimeValues.length > 0
      ? responseTimeValues.reduce((sum, time) => sum + time, 0) / responseTimeValues.length
      : 150; // Default if no data

    // Calculate error rate
    const errorRate = totalRequests > 0 ? (errorLogs / totalRequests) * 100 : 0;

    // Calculate throughput (requests per minute)
    const periodInMinutes = (endDate.getTime() - startDate.getTime()) / (1000 * 60);
    const throughput = periodInMinutes > 0 ? totalRequests / periodInMinutes : 0;

    // Calculate availability based on system downtime
    const systemErrors = systemLogs.filter(log =>
      log.action === 'SYSTEM_ERROR' || log.action === 'SYSTEM_RESTART'
    ).length;

    const totalPeriodHours = (endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60);
    const downtimeHours = systemErrors * 0.1; // Assume 6 minutes downtime per system error
    const availability = totalPeriodHours > 0
      ? Math.max(0, (1 - downtimeHours / totalPeriodHours) * 100)
      : 99.9;

    return {
      averageResponseTime: Math.round(averageResponseTime),
      errorRate: Math.round(errorRate * 100) / 100,
      throughput: Math.round(throughput),
      availability: Math.round(availability * 100) / 100,
    };
  }

  private static async getSecurityMetrics(startDate: Date, endDate: Date) {
    const [auditLogs, securityEvents, failedLogins, suspiciousLogs, blockedIPLogs] = await Promise.all([
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate } } }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          severity: { in: ['HIGH', 'CRITICAL'] },
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          action: 'LOGIN_FAILED',
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          OR: [
            { action: { contains: 'SUSPICIOUS' } },
            { metadata: { path: ['flags'], not: { equals: [] } } },
            { action: { contains: 'BRUTE_FORCE' } },
            { action: { contains: 'ANOMALY' } }
          ]
        }
      }),
      prisma.auditLog.findMany({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          OR: [
            { action: 'IP_BLOCKED' },
            { action: 'ACCESS_DENIED' },
            { metadata: { path: ['blocked'], equals: true } }
          ],
          ipAddress: { not: null }
        },
        select: { ipAddress: true },
        distinct: ['ipAddress']
      })
    ]);

    // Extract unique blocked IPs
    const blockedIPs = blockedIPLogs
      .map(log => log.ipAddress)
      .filter((ip): ip is string => ip !== null);

    return {
      auditLogs,
      securityEvents,
      failedLogins,
      suspiciousActivity: suspiciousLogs,
      blockedIPs,
    };
  }

  private static async getCandidateDemographics(candidateId: string) {
    // Get votes cast for this candidate
    const votes = await prisma.vote.findMany({
      where: { candidateId },
      include: {
        voter: {
          select: {
            faculty: true,
            yearOfStudy: true,
            department: true,
          },
        },
      },
    });

    // Group by faculty
    const byFaculty = votes.reduce((acc, vote) => {
      const faculty = vote.voter.faculty;
      acc[faculty] = (acc[faculty] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Group by year of study
    const byYear = votes.reduce((acc, vote) => {
      const year = vote.voter.yearOfStudy;
      acc[year] = (acc[year] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    return {
      byFaculty: Object.entries(byFaculty).map(([faculty, votes]) => ({
        faculty,
        votes,
      })),
      byYear: Object.entries(byYear).map(([year, votes]) => ({
        year: parseInt(year),
        votes,
      })),
    };
  }

  private static calculateCandidateAnalytics(performance: any[]) {
    const totalElections = performance.length;
    const totalVotes = performance.reduce((sum, p) => sum + p.totalVotes, 0);
    const wins = performance.filter(p => p.isWinner).length;
    const avgRank = performance.reduce((sum, p) => sum + p.rank, 0) / totalElections || 0;

    // Find strongest demographic by analyzing vote patterns
    let strongestDemographic = 'Unknown';

    if (performance.length > 0) {
      // Aggregate all demographic data
      const allFacultyVotes = performance.reduce((acc, p) => {
        p.demographics.byFaculty.forEach((demo: any) => {
          acc[demo.faculty] = (acc[demo.faculty] || 0) + demo.votes;
        });
        return acc;
      }, {} as Record<string, number>);

      // Find faculty with highest total votes
      const strongestFaculty = Object.entries(allFacultyVotes).reduce(
        (max, [faculty, votes]) => (votes as number) > max.votes ? { faculty, votes: votes as number } : max,
        { faculty: 'Unknown', votes: 0 }
      );

      strongestDemographic = strongestFaculty.faculty !== 'Unknown'
        ? `Faculty of ${strongestFaculty.faculty}`
        : 'No clear demographic preference';
    }

    return {
      totalElections,
      totalVotes,
      winRate: totalElections > 0 ? (wins / totalElections) * 100 : 0,
      averageRank: Math.round(avgRank * 100) / 100,
      strongestDemographic,
    };
  }

  private static async calculateVoterStatistics(votingHistory: any[], voterId: string) {
    const totalElections = votingHistory.length;
    const lastVote = votingHistory.length > 0 ? votingHistory[0].votedAt : undefined;

    // Calculate favorite election type
    const typeCounts = votingHistory.reduce((acc, vote) => {
      acc[vote.electionType] = (acc[vote.electionType] || 0) + 1;
      return acc;
    }, {});

    const favoriteType = Object.entries(typeCounts).reduce(
      (max: any, [type, count]: [string, any]) =>
        count > max.count ? { type, count } : max,
      { type: 'PRESIDENTIAL', count: 0 }
    ).type;

    // Calculate participation rate based on eligible elections
    const voter = await prisma.user.findUnique({
      where: { id: voterId },
      select: {
        faculty: true,
        department: true,
        course: true,
        yearOfStudy: true,
        createdAt: true,
      },
    });

    let participationRate = 100; // Default if we can't calculate

    if (voter) {
      // Count elections this voter was eligible for since their registration
      const eligibleElections = await prisma.election.count({
        where: {
          createdAt: { gte: voter.createdAt },
          OR: [
            { eligibleFaculties: { has: voter.faculty } },
            { eligibleDepartments: { has: voter.department } },
            { eligibleCourses: { has: voter.course } },
            { eligibleYears: { has: voter.yearOfStudy } },
            {
              AND: [
                { eligibleFaculties: { isEmpty: true } },
                { eligibleDepartments: { isEmpty: true } },
                { eligibleCourses: { isEmpty: true } },
                { eligibleYears: { isEmpty: true } },
              ],
            },
          ],
        },
      });

      participationRate = eligibleElections > 0 ? (totalElections / eligibleElections) * 100 : 100;
    }

    // Calculate average voting time from audit logs
    const votingTimes = await prisma.auditLog.findMany({
      where: {
        userId: voterId,
        action: 'VOTE_CAST',
        metadata: { not: {} },
      },
      select: { metadata: true },
    });

    const votingTimeValues = votingTimes
      .map(log => typeof log.metadata === 'object' && log.metadata !== null && 'votingTime' in log.metadata ? (log.metadata as any).votingTime as number : null)
      .filter((time): time is number => typeof time === 'number' && time > 0);

    const averageVotingTime = votingTimeValues.length > 0
      ? votingTimeValues.reduce((sum, time) => sum + time, 0) / votingTimeValues.length
      : 0;

    return {
      totalElectionsParticipated: totalElections,
      participationRate: Math.round(participationRate * 100) / 100,
      averageVotingTime: Math.round(averageVotingTime * 100) / 100,
      lastVoteDate: lastVote,
      favoriteElectionType: favoriteType,
    };
  }

  private static buildComparativeAnalysis(elections: ElectionReport[]) {
    return {
      elections: elections.map(e => ({
        title: e.election.title,
        turnout: e.election.turnoutPercentage,
        totalVotes: e.election.totalVotesCast,
        positions: e.positions.length,
      })),
      averageTurnout: elections.reduce((sum, e) => sum + e.election.turnoutPercentage, 0) / elections.length,
      trends: [], // TODO: Implement trend analysis
    };
  }

  private static categorizeAuditLogs(logs: any[]) {
    return logs.reduce((acc, log) => {
      acc[log.category] = (acc[log.category] || 0) + 1;
      return acc;
    }, {});
  }

  private static analyzeAuditTimeline(logs: any[]) {
    // Group by hour for timeline analysis
    const timeline = logs.reduce((acc, log) => {
      const hour = log.createdAt.getHours();
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {});

    return Array.from({ length: 24 }, (_, hour) => ({
      hour,
      count: timeline[hour] || 0,
    }));
  }

  private static assessAuditRisks(logs: any[]) {
    const highRisk = logs.filter(log => log.severity === 'HIGH' || log.severity === 'CRITICAL').length;
    const totalLogs = logs.length;

    return {
      riskScore: totalLogs > 0 ? (highRisk / totalLogs) * 100 : 0,
      highRiskEvents: highRisk,
      recommendations: highRisk > 10 ? ['Immediate security review required'] : ['System operating normally'],
    };
  }

  private static generateAnomalyDescription(log: any): string {
    const action = log.action;
    const metadata = log.metadata || {};

    switch (action) {
      case 'SUSPICIOUS_LOGIN_PATTERN':
        return `Unusual login pattern detected - multiple rapid attempts from different locations`;
      case 'VOTE_MANIPULATION_ATTEMPT':
        return `Potential vote manipulation detected - unusual voting patterns observed`;
      case 'DATA_INTEGRITY_VIOLATION':
        return `Data integrity check failed - inconsistent data detected`;
      case 'UNAUTHORIZED_ACCESS_ATTEMPT':
        return `Unauthorized access attempt to restricted resource`;
      case 'ANOMALY_DETECTED':
        return metadata.description || 'System anomaly detected requiring investigation';
      default:
        return `Security anomaly: ${action} requires attention`;
    }
  }
}

export default ReportingService;