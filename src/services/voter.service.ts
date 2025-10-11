// backend/src/services/voter.service.ts

import { PrismaClient, User, Election, Vote, VoterEligibility, VotingSession } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger, logAudit } from '../utils/logger';
import { AppError, ValidationError, NotFoundError } from '../utils/errors';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { HashingService } from '../utils/hashing';
import { encryptionService } from '../utils/encryption';
import { NotificationService } from './notification.service';

export interface VoterProfile {
  id: string;
  studentId: string;
  email: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  phone?: string;
  profileImage?: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  admissionYear: number;
  isVerified: boolean;
  isActive: boolean;
  emailVerified?: Date;
  phoneVerified?: Date;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface VoterStats {
  totalVoters: number;
  verifiedVoters: number;
  activeVoters: number;
  eligibleVoters: number;
  votersWhoVoted: number;
  participationRate: number;
  byFaculty: Record<string, { total: number; voted: number; percentage: number }>;
  byYear: Record<number, { total: number; voted: number; percentage: number }>;
  byDepartment: Record<string, { total: number; voted: number; percentage: number }>;
  registrationTrends: Array<{
    date: string;
    registrations: number;
    cumulative: number;
  }>;
  votingPatterns: {
    timeOfDay: Record<number, number>;
    dayOfWeek: Record<string, number>;
    deviceTypes: Record<string, number>;
  };
}

export interface VoterEligibilityCheck {
  isEligible: boolean;
  reasons: string[];
  requirements: {
    faculty: { required: string[]; userValue: string; matches: boolean };
    department: { required: string[]; userValue: string; matches: boolean };
    course: { required: string[]; userValue: string; matches: boolean };
    yearOfStudy: { required: number[]; userValue: number; matches: boolean };
    age: { min?: number; max?: number; userAge?: number; matches: boolean };
    isActive: { required: boolean; userValue: boolean; matches: boolean };
    isVerified: { required: boolean; userValue: boolean; matches: boolean };
  };
  election: {
    id: string;
    title: string;
    status: string;
    startDate: Date;
    endDate: Date;
  };
}

export interface VotingHistory {
  electionId: string;
  electionTitle: string;
  electionType: string;
  positionName: string;
  candidateName: string;
  votedAt: Date;
  verificationCode: string;
  voteHash: string;
  isVerified: boolean;
  deviceInfo?: any;
}

export interface VoterPreferences {
  emailNotifications: boolean;
  smsNotifications: boolean;
  pushNotifications: boolean;
  reminderFrequency: 'never' | 'daily' | 'weekly' | 'election_only';
  language: 'en' | 'sw';
  theme: 'light' | 'dark' | 'system';
  accessibility: {
    highContrast: boolean;
    largeText: boolean;
    screenReader: boolean;
  };
}

export interface VoterRegistrationData {
  studentId: string;
  email: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  phone?: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  admissionYear: number;
  password: string;
  confirmPassword: string;
}

export interface VoterSearchFilters {
  faculty?: string;
  department?: string;
  course?: string;
  yearOfStudy?: number;
  admissionYear?: number;
  isVerified?: boolean;
  isActive?: boolean;
  hasVoted?: boolean;
  electionId?: string;
  search?: string;
  registeredAfter?: Date;
  registeredBefore?: Date;
  lastLoginAfter?: Date;
  lastLoginBefore?: Date;
}

export class VoterService {
  private static instance: VoterService;
  private static readonly CACHE_TTL = 300; // 5 minutes
  private static readonly BATCH_SIZE = 100;
  private static readonly MAX_LOGIN_ATTEMPTS = 5;
  private static readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

  private constructor() {
    // Private constructor for singleton
  }

  public static getInstance(): VoterService {
    if (!VoterService.instance) {
      VoterService.instance = new VoterService();
    }
    return VoterService.instance;
  }

  /**
   * Register a new voter
   */
  public async registerVoter(
    registrationData: VoterRegistrationData,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ voter: VoterProfile; verificationToken: string }> {
    return await prisma.$transaction(async (tx) => {
      // Validate passwords match
      if (registrationData.password !== registrationData.confirmPassword) {
        throw new ValidationError('Passwords do not match');
      }

      // Check if user already exists
      const existingUser = await tx.user.findFirst({
        where: {
          OR: [
            { email: registrationData.email.toLowerCase() },
            { studentId: registrationData.studentId.toUpperCase() },
          ],
        },
      });

      if (existingUser) {
        throw new AppError('User with this email or student ID already exists', 409);
      }

      // Validate student ID format (JKUAT format)
      const studentIdRegex = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
      if (!studentIdRegex.test(registrationData.studentId)) {
        throw new ValidationError('Invalid student ID format. Expected format: ABC123-1234/2023');
      }

      // Validate email domain (optional JKUAT domain check)
      const emailDomain = registrationData.email.split('@')[1];
      const allowedDomains = ['students.jkuat.ac.ke', 'jkuat.ac.ke', 'gmail.com', 'yahoo.com', 'outlook.com'];
      if (process.env.ENFORCE_JKUAT_EMAIL === 'true' && !allowedDomains.includes(emailDomain)) {
        throw new ValidationError('Please use a valid institutional email address');
      }

      // Hash password
      const hashedPassword = await HashingService.hashPassword(registrationData.password);

      // Generate verification token
      const verificationToken = encryptionService.generateToken(32);
      const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Create user
      const user = await tx.user.create({
        data: {
          studentId: registrationData.studentId.toUpperCase(),
          email: registrationData.email.toLowerCase(),
          firstName: registrationData.firstName.trim(),
          lastName: registrationData.lastName.trim(),
          middleName: registrationData.middleName?.trim(),
          phone: registrationData.phone?.trim(),
          faculty: registrationData.faculty,
          department: registrationData.department,
          course: registrationData.course,
          yearOfStudy: registrationData.yearOfStudy,
          admissionYear: registrationData.admissionYear,
          password: hashedPassword,
          role: 'VOTER',
          isActive: true,
          isVerified: false,
          permissions: [],
        },
      });

      // Create verification token
      await tx.verificationToken.create({
        data: {
          userId: user.id,
          token: verificationToken,
          type: 'EMAIL_VERIFICATION',
          expiresAt: tokenExpiry,
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'VOTER_REGISTRATION',
          category: 'USER',
          severity: 'MEDIUM',
          userId: user.id,
          entityType: 'User',
          entityId: user.id,
          ipAddress,
          userAgent,
          newData: {
            studentId: user.studentId,
            email: user.email,
            faculty: user.faculty,
            department: user.department,
          },
        },
      });

      // Send verification email
      await emailService.sendEmail({
        to: user.email,
        subject: 'Verify Your JKUAT Voting System Account',
        template: 'email-verification',
        data: {
          firstName: user.firstName,
          verificationUrl: `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`,
          expiresIn: '24 hours',
        },
      });

      logger.info('Voter registered successfully', {
        userId: user.id,
        studentId: user.studentId,
        email: user.email,
        faculty: user.faculty,
      });

      return {
        voter: this.formatVoterProfile(user),
        verificationToken,
      };
    });
  }

  /**
   * Verify voter email
   */
  public async verifyEmail(
    token: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<VoterProfile> {
    return await prisma.$transaction(async (tx) => {
      const verificationToken = await tx.verificationToken.findFirst({
        where: {
          token,
          type: 'EMAIL_VERIFICATION',
          expiresAt: { gt: new Date() },
        },
        include: { user: true },
      });

      if (!verificationToken) {
        throw new AppError('Invalid or expired verification token', 400);
      }

      const user = await tx.user.update({
        where: { id: verificationToken.userId },
        data: {
          isVerified: true,
          emailVerified: new Date(),
        },
      });

      // Delete verification token
      await tx.verificationToken.delete({
        where: { id: verificationToken.id },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'EMAIL_VERIFIED',
          category: 'USER',
          severity: 'LOW',
          userId: user.id,
          entityType: 'User',
          entityId: user.id,
          ipAddress,
          userAgent,
        },
      });

      // Send welcome notification
      await NotificationService.createNotification({
        userId: user.id,
        title: 'Welcome to JKUAT Voting System!',
        message: 'Your email has been verified successfully. You can now participate in elections.',
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email'],
      });

      logger.info('Email verified successfully', {
        userId: user.id,
        email: user.email,
      });

      return this.formatVoterProfile(user);
    });
  }

  /**
   * Get voter profile
   */
  public async getVoterProfile(
    userId: string,
    includeStats: boolean = false
  ): Promise<VoterProfile & { stats?: any }> {
    const cacheKey = `voter:profile:${userId}`;

    if (!includeStats) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: includeStats ? {
        votes: {
          include: {
            election: { select: { title: true, type: true } },
            position: { select: { name: true } },
          },
        },
        _count: {
          select: { votes: true },
        },
      } : undefined,
    });

    if (!user) {
      throw new NotFoundError('Voter not found');
    }

    const profile = this.formatVoterProfile(user);

    if (includeStats && 'votes' in user && '_count' in user) {
      const userVotes = user.votes as any[];
      const stats = {
        totalVotesCast: (user as any)._count.votes,
        electionsParticipated: new Set(userVotes.map((v: any) => v.electionId)).size,
        lastVoteDate: userVotes.length > 0 ? userVotes[userVotes.length - 1].castAt : null,
        votesByType: userVotes.reduce((acc: any, vote: any) => {
          const type = vote.election.type;
          acc[type] = (acc[type] || 0) + 1;
          return acc;
        }, {}),
      };

      (profile as any).stats = stats;
    }

    if (!includeStats) {
      await redis.setex(cacheKey, VoterService.CACHE_TTL, JSON.stringify(profile));
    }

    return profile;
  }

  /**
   * Update voter profile
   */
  public async updateVoterProfile(
    userId: string,
    updateData: {
      firstName?: string;
      lastName?: string;
      middleName?: string;
      phone?: string;
      profileImage?: string;
    },
    updatedBy: string = userId
  ): Promise<VoterProfile> {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: userId } });

      if (!user) {
        throw new NotFoundError('Voter not found');
      }

      const oldData = {
        firstName: user.firstName,
        lastName: user.lastName,
        middleName: user.middleName,
        phone: user.phone,
        profileImage: user.profileImage,
      };

      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: {
          ...updateData,
          updatedAt: new Date(),
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'VOTER_PROFILE_UPDATED',
          category: 'USER',
          severity: 'LOW',
          userId: updatedBy,
          entityType: 'User',
          entityId: userId,
          oldData,
          newData: updateData,
        },
      });

      // Clear cache
      await redis.del(`voter:profile:${userId}`);

      logger.info('Voter profile updated', {
        userId,
        updatedBy,
        fields: Object.keys(updateData),
      });

      return this.formatVoterProfile(updatedUser);
    });
  }

  /**
   * Check voter eligibility for an election
   */
  public async checkVoterEligibility(
    userId: string,
    electionId: string
  ): Promise<VoterEligibilityCheck> {
    const [user, election] = await Promise.all([
      prisma.user.findUnique({ where: { id: userId } }),
      prisma.election.findUnique({
        where: { id: electionId },
        include: { voterEligibility: { where: { userId } } }
      }),
    ]);

    if (!user) {
      throw new NotFoundError('Voter not found');
    }

    if (!election) {
      throw new NotFoundError('Election not found');
    }

    const reasons: string[] = [];
    let isEligible = true;

    // Check basic requirements
    const requirements = {
      faculty: {
        required: election.eligibleFaculties,
        userValue: user.faculty,
        matches: election.eligibleFaculties.length === 0 || election.eligibleFaculties.includes(user.faculty),
      },
      department: {
        required: election.eligibleDepartments,
        userValue: user.department,
        matches: election.eligibleDepartments.length === 0 || election.eligibleDepartments.includes(user.department),
      },
      course: {
        required: election.eligibleCourses,
        userValue: user.course,
        matches: election.eligibleCourses.length === 0 || election.eligibleCourses.includes(user.course),
      },
      yearOfStudy: {
        required: election.eligibleYears,
        userValue: user.yearOfStudy,
        matches: election.eligibleYears.length === 0 || election.eligibleYears.includes(user.yearOfStudy),
      },
      age: {
        min: election.minVoterAge ?? undefined,
        max: election.maxVoterAge ?? undefined,
        userAge: this.calculateAge(user.admissionYear),
        matches: this.checkAgeEligibility(user.admissionYear, election.minVoterAge ?? undefined, election.maxVoterAge ?? undefined),
      },
      isActive: {
        required: true,
        userValue: user.isActive,
        matches: user.isActive,
      },
      isVerified: {
        required: true,
        userValue: user.isVerified,
        matches: user.isVerified,
      },
    };

    // Check each requirement
    if (!requirements.faculty.matches) {
      reasons.push(`Faculty not eligible. Required: ${requirements.faculty.required.join(', ')}`);
      isEligible = false;
    }

    if (!requirements.department.matches) {
      reasons.push(`Department not eligible. Required: ${requirements.department.required.join(', ')}`);
      isEligible = false;
    }

    if (!requirements.course.matches) {
      reasons.push(`Course not eligible. Required: ${requirements.course.required.join(', ')}`);
      isEligible = false;
    }

    if (!requirements.yearOfStudy.matches) {
      reasons.push(`Year of study not eligible. Required: ${requirements.yearOfStudy.required.join(', ')}`);
      isEligible = false;
    }

    if (!requirements.age.matches) {
      reasons.push(`Age not within required range`);
      isEligible = false;
    }

    if (!requirements.isActive.matches) {
      reasons.push('Account is not active');
      isEligible = false;
    }

    if (!requirements.isVerified.matches) {
      reasons.push('Email not verified');
      isEligible = false;
    }

    // Check if explicitly eligible
    if (election.voterEligibility.length > 0) {
      isEligible = true;
      reasons.length = 0; // Clear previous reasons as explicit eligibility overrides
    }

    // Check election timing
    const now = new Date();
    if (now < election.startDate) {
      reasons.push('Election has not started yet');
      isEligible = false;
    }

    if (now > election.endDate) {
      reasons.push('Election has ended');
      isEligible = false;
    }

    if (election.status !== 'ACTIVE' && election.status !== 'SCHEDULED') {
      reasons.push('Election is not active');
      isEligible = false;
    }

    return {
      isEligible,
      reasons,
      requirements,
      election: {
        id: election.id,
        title: election.title,
        status: election.status,
        startDate: election.startDate,
        endDate: election.endDate,
      },
    };
  }

  /**
   * Get voter's voting history
   */
  public async getVotingHistory(
    userId: string,
    filters: {
      electionId?: string;
      electionType?: string;
      fromDate?: Date;
      toDate?: Date;
    } = {},
    page: number = 1,
    limit: number = 20
  ) {
    const where: any = { voterId: userId };

    if (filters.electionId) {
      where.electionId = filters.electionId;
    }

    if (filters.electionType) {
      where.election = { type: filters.electionType };
    }

    if (filters.fromDate || filters.toDate) {
      where.castAt = {};
      if (filters.fromDate) where.castAt.gte = filters.fromDate;
      if (filters.toDate) where.castAt.lte = filters.toDate;
    }

    const [votes, total] = await Promise.all([
      prisma.vote.findMany({
        where,
        include: {
          election: { select: { title: true, type: true } },
          position: { select: { name: true } },
          candidate: {
            select: { firstName: true, lastName: true },
          },
        },
        orderBy: { castAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.vote.count({ where }),
    ]);

    const votingHistory: VotingHistory[] = votes.map(vote => ({
      electionId: vote.electionId,
      electionTitle: vote.election.title,
      electionType: vote.election.type,
      positionName: vote.position.name,
      candidateName: vote.candidate
        ? `${vote.candidate.firstName} ${vote.candidate.lastName}`
        : 'Abstain',
      votedAt: vote.castAt,
      verificationCode: vote.verificationCode,
      voteHash: vote.voteHash || '',
      isVerified: vote.verified,
      deviceInfo: undefined,
    }));

    return {
      votingHistory,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: limit,
        hasNext: page < Math.ceil(total / limit),
        hasPrevious: page > 1,
      },
    };
  }

  /**
   * Get voters with search and filtering
   */
  public async getVoters(
    filters: VoterSearchFilters = {},
    page: number = 1,
    limit: number = 50,
    sortBy: 'createdAt' | 'lastName' | 'studentId' | 'lastLogin' = 'createdAt',
    sortOrder: 'asc' | 'desc' = 'desc'
  ) {
    const where: any = { role: 'VOTER' };

    // Apply filters
    if (filters.faculty) where.faculty = filters.faculty;
    if (filters.department) where.department = filters.department;
    if (filters.course) where.course = filters.course;
    if (filters.yearOfStudy) where.yearOfStudy = filters.yearOfStudy;
    if (filters.admissionYear) where.admissionYear = filters.admissionYear;
    if (typeof filters.isVerified === 'boolean') where.isVerified = filters.isVerified;
    if (typeof filters.isActive === 'boolean') where.isActive = filters.isActive;

    if (filters.registeredAfter || filters.registeredBefore) {
      where.createdAt = {};
      if (filters.registeredAfter) where.createdAt.gte = filters.registeredAfter;
      if (filters.registeredBefore) where.createdAt.lte = filters.registeredBefore;
    }

    if (filters.lastLoginAfter || filters.lastLoginBefore) {
      where.lastLogin = {};
      if (filters.lastLoginAfter) where.lastLogin.gte = filters.lastLoginAfter;
      if (filters.lastLoginBefore) where.lastLogin.lte = filters.lastLoginBefore;
    }

    if (filters.search) {
      where.OR = [
        { firstName: { contains: filters.search, mode: 'insensitive' } },
        { lastName: { contains: filters.search, mode: 'insensitive' } },
        { studentId: { contains: filters.search, mode: 'insensitive' } },
        { email: { contains: filters.search, mode: 'insensitive' } },
      ];
    }

    // Check voting status if filter applied
    if (typeof filters.hasVoted === 'boolean' && filters.electionId) {
      if (filters.hasVoted) {
        where.votes = { some: { electionId: filters.electionId } };
      } else {
        where.votes = { none: { electionId: filters.electionId } };
      }
    }

    const [voters, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true,
          studentId: true,
          email: true,
          firstName: true,
          lastName: true,
          middleName: true,
          phone: true,
          profileImage: true,
          faculty: true,
          department: true,
          course: true,
          yearOfStudy: true,
          admissionYear: true,
          isVerified: true,
          isActive: true,
          emailVerified: true,
          phoneVerified: true,
          lastLogin: true,
          createdAt: true,
          updatedAt: true,
          _count: {
            select: { votes: true },
          },
        },
        orderBy: { [sortBy]: sortOrder },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.user.count({ where }),
    ]);

    return {
      voters: voters.map(voter => ({
        ...this.formatVoterProfile(voter),
        totalVotes: voter._count.votes,
      })),
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: limit,
        hasNext: page < Math.ceil(total / limit),
        hasPrevious: page > 1,
      },
    };
  }

  /**
   * Get voter statistics
   */
  public async getVoterStatistics(
    electionId?: string,
    useCache: boolean = true
  ): Promise<VoterStats> {
    const cacheKey = electionId ? `voter-stats:${electionId}` : 'voter-stats:global';

    if (useCache) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const [
      totalVoters,
      verifiedVoters,
      activeVoters,
      votersByFaculty,
      votersByYear,
      votersByDepartment,
      registrationTrends,
    ] = await Promise.all([
      prisma.user.count({ where: { role: 'VOTER' } }),
      prisma.user.count({ where: { role: 'VOTER', isVerified: true } }),
      prisma.user.count({ where: { role: 'VOTER', isActive: true } }),
      // Faculty breakdown
      prisma.user.groupBy({
        by: ['faculty'],
        where: { role: 'VOTER' },
        _count: true,
      }),
      // Year breakdown
      prisma.user.groupBy({
        by: ['yearOfStudy'],
        where: { role: 'VOTER' },
        _count: true,
      }),
      // Department breakdown
      prisma.user.groupBy({
        by: ['department'],
        where: { role: 'VOTER' },
        _count: true,
      }),
      // Registration trends (last 30 days)
      this.getRegistrationTrends(),
    ]);

    // Get voting data if election specified
    let votingData: any = {};
    let eligibleVoters = totalVoters;
    let votersWhoVoted = 0;

    if (electionId) {
      const election = await prisma.election.findUnique({
        where: { id: electionId },
        include: {
          votes: {
            select: { voterId: true },
            distinct: ['voterId'],
          },
          voterEligibility: true,
        },
      });

      if (election) {
        eligibleVoters = election.totalEligibleVoters;
        votersWhoVoted = election.votes.length;

        // Get voting patterns for this election
        const votes = await prisma.vote.findMany({
          where: { electionId },
          include: { voter: { select: { faculty: true, department: true, yearOfStudy: true } } },
        });

        votingData = this.calculateVotingPatterns(votes);
      }
    }

    const participationRate = eligibleVoters > 0 ? (votersWhoVoted / eligibleVoters) * 100 : 0;

    const stats: VoterStats = {
      totalVoters,
      verifiedVoters,
      activeVoters,
      eligibleVoters,
      votersWhoVoted,
      participationRate: Math.round(participationRate * 100) / 100,
      byFaculty: this.formatDemographicStats(votersByFaculty, 'faculty', electionId),
      byYear: this.formatDemographicStats(votersByYear, 'yearOfStudy', electionId),
      byDepartment: this.formatDemographicStats(votersByDepartment, 'department', electionId),
      registrationTrends,
      votingPatterns: votingData.patterns || {
        timeOfDay: {},
        dayOfWeek: {},
        deviceTypes: {},
      },
    };

    if (useCache) {
      await redis.setex(cacheKey, VoterService.CACHE_TTL, JSON.stringify(stats));
    }

    return stats;
  }

  /**
   * Add voters to election eligibility list
   */
  public async addVotersToElection(
    electionId: string,
    voterIds: string[],
    addedBy: string,
    reason?: string
  ): Promise<{ added: number; failed: number; errors: string[] }> {
    const result = { added: 0, failed: 0, errors: [] as string[] };

    // Process in batches
    for (let i = 0; i < voterIds.length; i += VoterService.BATCH_SIZE) {
      const batch = voterIds.slice(i, i + VoterService.BATCH_SIZE);

      await Promise.allSettled(
        batch.map(async (voterId) => {
          try {
            await prisma.voterEligibility.create({
              data: {
                electionId,
                userId: voterId,
                addedBy,
                reason,
              },
            });
            result.added++;
          } catch (error: any) {
            result.failed++;
            result.errors.push(`Voter ${voterId}: ${error.message}`);
          }
        })
      );
    }

    // Create audit log
    await prisma.auditLog.create({
      data: {
        action: 'VOTERS_ADDED_TO_ELECTION',
        category: 'ELECTION',
        severity: 'MEDIUM',
        userId: addedBy,
        electionId,
        metadata: {
          voterCount: voterIds.length,
          added: result.added,
          failed: result.failed,
          reason,
        },
      },
    });

    logger.info('Voters added to election', {
      electionId,
      addedBy,
      total: voterIds.length,
      added: result.added,
      failed: result.failed,
    });

    return result;
  }

  // Private helper methods

  private formatVoterProfile(user: any): VoterProfile {
    return {
      id: user.id,
      studentId: user.studentId,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      middleName: user.middleName,
      phone: user.phone,
      profileImage: user.profileImage,
      faculty: user.faculty,
      department: user.department,
      course: user.course,
      yearOfStudy: user.yearOfStudy,
      admissionYear: user.admissionYear,
      isVerified: user.isVerified,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private calculateAge(admissionYear: number): number {
    // Estimate age based on admission year (assuming 18 at admission)
    const currentYear = new Date().getFullYear();
    return 18 + (currentYear - admissionYear);
  }

  private checkAgeEligibility(
    admissionYear: number,
    minAge?: number,
    maxAge?: number
  ): boolean {
    if (!minAge && !maxAge) return true;

    const age = this.calculateAge(admissionYear);

    if (minAge && age < minAge) return false;
    if (maxAge && age > maxAge) return false;

    return true;
  }

  private async getRegistrationTrends(): Promise<Array<{
    date: string;
    registrations: number;
    cumulative: number;
  }>> {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const registrations = await prisma.user.findMany({
      where: {
        role: 'VOTER',
        createdAt: { gte: thirtyDaysAgo },
      },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    const dailyStats = new Map<string, number>();
    let cumulative = 0;

    registrations.forEach(reg => {
      const date = reg.createdAt.toISOString().split('T')[0];
      dailyStats.set(date, (dailyStats.get(date) || 0) + 1);
    });

    const trends = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      const count = dailyStats.get(dateStr) || 0;
      cumulative += count;

      trends.push({
        date: dateStr,
        registrations: count,
        cumulative,
      });
    }

    return trends;
  }

  private calculateVotingPatterns(votes: any[]): { patterns: any } {
    const patterns = {
      timeOfDay: {} as Record<number, number>,
      dayOfWeek: {} as Record<string, number>,
      deviceTypes: {} as Record<string, number>,
    };

    votes.forEach(vote => {
      const castDate = new Date(vote.castAt);

      // Time of day
      const hour = castDate.getHours();
      patterns.timeOfDay[hour] = (patterns.timeOfDay[hour] || 0) + 1;

      // Day of week
      const dayOfWeek = castDate.toLocaleDateString('en-US', { weekday: 'long' });
      patterns.dayOfWeek[dayOfWeek] = (patterns.dayOfWeek[dayOfWeek] || 0) + 1;

      // Device types (if available in deviceInfo)
      if (vote.deviceInfo && vote.deviceInfo.type) {
        patterns.deviceTypes[vote.deviceInfo.type] = (patterns.deviceTypes[vote.deviceInfo.type] || 0) + 1;
      }
    });

    return { patterns };
  }

  private formatDemographicStats(
    groupedData: any[],
    field: string,
    electionId?: string
  ): Record<string, { total: number; voted: number; percentage: number }> {
    const stats: Record<string, { total: number; voted: number; percentage: number }> = {};

    groupedData.forEach(item => {
      const key = field === 'yearOfStudy' ? item.yearOfStudy.toString() : item[field];
      stats[key] = {
        total: item._count,
        voted: 0, // Would need additional query for election-specific data
        percentage: 0,
      };
    });

    return stats;
  }

  /**
   * Upload voter profile picture
   */
  public async uploadProfilePicture(
    userId: string,
    file: Express.Multer.File
  ): Promise<{ profileImageUrl: string }> {
    // Implementation would depend on your file upload service
    // This is a placeholder implementation
    throw new AppError('Profile picture upload not yet implemented', 501);
  }

  /**
   * Check election eligibility (alias for checkVoterEligibility)
   */
  public async checkElectionEligibility(
    userId: string,
    electionId: string
  ): Promise<VoterEligibilityCheck> {
    return this.checkVoterEligibility(userId, electionId);
  }

  /**
   * Get voter statistics with filters (used by controller)
   */
  public async getVoterStatisticsWithFilters(filters: {
    faculty?: string;
    department?: string;
    yearOfStudy?: number;
    admissionYear?: number;
    period?: string;
  }): Promise<VoterStats> {
    // Convert filters to the expected format and call the main method
    return this.getVoterStatistics(undefined, true);
  }

  /**
   * Search voters with comprehensive filters
   */
  public async searchVoters(filters: {
    search?: string;
    faculty?: string;
    department?: string;
    course?: string;
    yearOfStudy?: number;
    admissionYear?: number;
    isVerified?: boolean;
    isActive?: boolean;
    hasVoted?: boolean;
    electionId?: string;
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }) {
    const {
      page = 1,
      limit = 50,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      ...searchFilters
    } = filters;

    return this.getVoters(
      searchFilters,
      page,
      limit,
      sortBy as 'createdAt' | 'lastName' | 'studentId' | 'lastLogin',
      sortOrder
    );
  }

  /**
   * Update voter status
   */
  public async updateVoterStatus(
    voterId: string,
    statusData: {
      status: string;
      reason?: string;
      suspensionEndDate?: Date;
      updatedBy: string;
    }
  ): Promise<VoterProfile> {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: voterId } });

      if (!user) {
        throw new NotFoundError('Voter not found');
      }

      const updatedUser = await tx.user.update({
        where: { id: voterId },
        data: {
          isActive: statusData.status === 'ACTIVE',
          updatedAt: new Date(),
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'VOTER_STATUS_UPDATED',
          category: 'USER',
          severity: 'HIGH',
          userId: statusData.updatedBy,
          entityType: 'User',
          entityId: voterId,
          metadata: {
            oldStatus: user.isActive ? 'ACTIVE' : 'INACTIVE',
            newStatus: statusData.status,
            reason: statusData.reason,
            suspensionEndDate: statusData.suspensionEndDate,
          },
        },
      });

      // Clear cache
      await redis.del(`voter:profile:${voterId}`);

      return this.formatVoterProfile(updatedUser);
    });
  }

  /**
   * Resend email verification
   */
  public async resendEmailVerification(userId: string): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      throw new NotFoundError('Voter not found');
    }

    if (user.isVerified) {
      throw new AppError('Email is already verified', 400);
    }

    // Generate new verification token
    const verificationToken = encryptionService.generateToken(32);
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await prisma.verificationToken.create({
      data: {
        userId: user.id,
        token: verificationToken,
        type: 'EMAIL_VERIFICATION',
        expiresAt: tokenExpiry,
      },
    });

    // Send verification email
    await emailService.sendEmail({
      to: user.email,
      subject: 'Verify Your JKUAT Voting System Account',
      template: 'email-verification',
      data: {
        firstName: user.firstName,
        verificationUrl: `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`,
        expiresIn: '24 hours',
      },
    });
  }

  /**
   * Update voter preferences
   */
  public async updatePreferences(
    userId: string,
    preferences: VoterPreferences
  ): Promise<VoterPreferences> {
    // Implementation would depend on your preferences storage strategy
    // This is a placeholder implementation
    throw new AppError('Preferences update not yet implemented', 501);
  }

  /**
   * Get voter preferences
   */
  public async getPreferences(userId: string): Promise<VoterPreferences> {
    // Implementation would depend on your preferences storage strategy
    // This is a placeholder implementation
    throw new AppError('Preferences retrieval not yet implemented', 501);
  }

  /**
   * Import voters from file
   */
  public async importVoters(
    file: Express.Multer.File,
    options: {
      format: string;
      overwriteExisting: boolean;
      sendWelcomeEmails: boolean;
      importedBy: string;
    }
  ): Promise<{
    totalRecords: number;
    successfulImports: number;
    failedImports: number;
    errors: string[];
  }> {
    // Implementation would depend on your file processing strategy
    // This is a placeholder implementation
    throw new AppError('Voter import not yet implemented', 501);
  }

  /**
   * Bulk import voters from parsed data
   */
  public async bulkImportVotersData(data: {
    voters: Array<{
      studentId: string;
      email: string;
      firstName: string;
      lastName: string;
      middleName?: string;
      phone?: string;
      faculty: string;
      department: string;
      course: string;
      yearOfStudy: number;
      admissionYear: number;
    }>;
    options: {
      overwriteExisting: boolean;
      sendWelcomeEmails: boolean;
      defaultPassword?: string;
      importedBy: string;
    };
  }): Promise<{
    totalRecords: number;
    successfulImports: number;
    failedImports: number;
    errors: Array<{ row: number; field?: string; message: string }>;
    warnings: Array<{ row: number; message: string }>;
  }> {
    const { voters, options } = data;
    const errors: Array<{ row: number; field?: string; message: string }> = [];
    const warnings: Array<{ row: number; message: string }> = [];
    let successfulImports = 0;
    let failedImports = 0;

    return await prisma.$transaction(async (tx) => {
      for (let i = 0; i < voters.length; i++) {
        const voter = voters[i];
        const rowNumber = i + 2; // Account for header row and 1-indexing

        try {
          // Check if voter already exists
          const existingUser = await tx.user.findFirst({
            where: {
              OR: [
                { email: voter.email.toLowerCase() },
                { studentId: voter.studentId.toUpperCase() },
              ],
            },
          });

          if (existingUser && !options.overwriteExisting) {
            warnings.push({
              row: rowNumber,
              message: `Voter with student ID ${voter.studentId} or email ${voter.email} already exists`,
            });
            failedImports++;
            continue;
          }

          // Generate password
          const password = options.defaultPassword || this.generateRandomPassword();
          const hashedPassword = await HashingService.hashPassword(password);

          // Normalize phone number
          let normalizedPhone = voter.phone;
          if (normalizedPhone && normalizedPhone.startsWith('0')) {
            normalizedPhone = '+254' + normalizedPhone.substring(1);
          }

          if (existingUser && options.overwriteExisting) {
            // Update existing voter
            await tx.user.update({
              where: { id: existingUser.id },
              data: {
                firstName: voter.firstName.trim(),
                lastName: voter.lastName.trim(),
                middleName: voter.middleName?.trim() || null,
                phone: normalizedPhone || null,
                faculty: voter.faculty.trim(),
                department: voter.department.trim(),
                course: voter.course.trim(),
                yearOfStudy: voter.yearOfStudy,
                admissionYear: voter.admissionYear,
                updatedAt: new Date(),
              },
            });

            successfulImports++;
          } else {
            // Create new voter
            await tx.user.create({
              data: {
                studentId: voter.studentId.toUpperCase().trim(),
                email: voter.email.toLowerCase().trim(),
                firstName: voter.firstName.trim(),
                lastName: voter.lastName.trim(),
                middleName: voter.middleName?.trim() || null,
                phone: normalizedPhone || null,
                password: hashedPassword,
                faculty: voter.faculty.trim(),
                department: voter.department.trim(),
                course: voter.course.trim(),
                yearOfStudy: voter.yearOfStudy,
                admissionYear: voter.admissionYear,
                role: 'VOTER',
                isVerified: false,
                isActive: true,
              },
            });

            successfulImports++;

            // Send welcome email if option is enabled
            if (options.sendWelcomeEmails) {
              try {
                await emailService.sendEmail({
                  to: voter.email,
                  subject: 'Welcome to JKUAT Voting System',
                  template: 'welcome',
                  data: {
                    name: `${voter.firstName} ${voter.lastName}`,
                    studentId: voter.studentId,
                    temporaryPassword: password,
                  },
                });
              } catch (emailError) {
                logger.warn(`Failed to send welcome email to ${voter.email}:`, emailError);
                warnings.push({
                  row: rowNumber,
                  message: `Voter created but failed to send welcome email`,
                });
              }
            }
          }
        } catch (error: any) {
          logger.error(`Error importing voter at row ${rowNumber}:`, error);
          errors.push({
            row: rowNumber,
            message: error.message || 'Unknown error during import',
          });
          failedImports++;
        }
      }

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'VOTERS_BULK_IMPORTED',
          category: 'USER',
          severity: 'HIGH',
          userId: options.importedBy,
          metadata: {
            totalRecords: voters.length,
            successfulImports,
            failedImports,
            errorCount: errors.length,
            warningCount: warnings.length,
          },
        },
      });

      return {
        totalRecords: voters.length,
        successfulImports,
        failedImports,
        errors,
        warnings,
      };
    });
  }

  /**
   * Generate a random password
   */
  private generateRandomPassword(): string {
    const length = 12;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';

    // Ensure at least one of each required character type
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
    password += '0123456789'[Math.floor(Math.random() * 10)];
    password += '!@#$%^&*'[Math.floor(Math.random() * 8)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }

    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
  }

  /**
   * Export voters data
   */
  public async exportVoters(options: {
    format: string;
    includePersonalData: boolean;
    includeVotingHistory: boolean;
    includeStatistics: boolean;
    filters: any;
    exportedBy: string;
  }): Promise<{
    recordCount: number;
    mimeType: string;
    filename: string;
    buffer?: Buffer;
    data?: any;
  }> {
    // Implementation would depend on your export strategy
    // This is a placeholder implementation
    throw new AppError('Voter export not yet implemented', 501);
  }

  /**
   * Bulk operations on voters
   */
  public async bulkVoterOperations(options: {
    operation: string;
    voterIds: string[];
    reason?: string;
    suspensionEndDate?: Date;
    operatedBy: string;
  }): Promise<{
    successfulOperations: number;
    failedOperations: number;
    errors: string[];
  }> {
    // Implementation would depend on your bulk operations strategy
    // This is a placeholder implementation
    throw new AppError('Bulk voter operations not yet implemented', 501);
  }

  /**
   * Get voter by ID with detailed information
   */
  public async getVoterById(
    voterId: string,
    options: {
      includeVotingHistory?: boolean;
      includeEligibility?: boolean;
      includeAuditLog?: boolean;
    } = {}
  ): Promise<VoterProfile & { additionalData?: any }> {
    const user = await prisma.user.findUnique({
      where: { id: voterId },
      include: {
        votes: options.includeVotingHistory ? {
          include: {
            election: { select: { title: true, type: true } },
            position: { select: { name: true } },
            candidate: { select: { firstName: true, lastName: true } },
          },
        } : false,
        // Add other includes based on options
      },
    });

    if (!user) {
      throw new NotFoundError('Voter not found');
    }

    const profile = this.formatVoterProfile(user);

    if (options.includeVotingHistory && 'votes' in user) {
      (profile as any).votingHistory = user.votes;
    }

    return profile;
  }

  /**
   * Delete voter account
   */
  public async deleteVoter(
    voterId: string,
    options: {
      reason: string;
      hardDelete: boolean;
      deletedBy: string;
    }
  ): Promise<{ studentId: string }> {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: voterId } });

      if (!user) {
        throw new NotFoundError('Voter not found');
      }

      if (options.hardDelete) {
        // Hard delete - remove from database
        await tx.user.delete({ where: { id: voterId } });
      } else {
        // Soft delete - mark as inactive
        await tx.user.update({
          where: { id: voterId },
          data: {
            isActive: false,
            email: `deleted_${Date.now()}_${user.email}`,
            studentId: `deleted_${Date.now()}_${user.studentId}`,
          },
        });
      }

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'VOTER_DELETED',
          category: 'USER',
          severity: 'CRITICAL',
          userId: options.deletedBy,
          entityType: 'User',
          entityId: voterId,
          metadata: {
            reason: options.reason,
            hardDelete: options.hardDelete,
            studentId: user.studentId,
          },
        },
      });

      // Clear cache
      await redis.del(`voter:profile:${voterId}`);

      return { studentId: user.studentId };
    });
  }

  /**
   * Generate analytics report
   */
  public async generateAnalyticsReport(options: {
    reportType: string;
    period: string;
    includeCharts: boolean;
    format: string;
    generatedBy: string;
  }): Promise<{
    size: number;
    mimeType: string;
    filename: string;
    buffer?: Buffer;
    data?: any;
  }> {
    // Implementation would depend on your analytics strategy
    // This is a placeholder implementation
    throw new AppError('Analytics report generation not yet implemented', 501);
  }

  /**
   * Clear voter-related caches
   */
  public async clearVoterCache(userId?: string): Promise<void> {
    const patterns = userId
      ? [`voter:profile:${userId}`, `voter-stats:*`]
      : ['voter:*', 'voter-stats:*'];

    for (const pattern of patterns) {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }
  }
}

export default VoterService;