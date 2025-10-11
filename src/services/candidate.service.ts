import { PrismaClient, Candidate, CandidateStatus, ElectionType } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { logger, logAudit } from '../utils/logger';
import { AppError, ValidationError } from '../utils/errors';
import { encryptionService } from '../utils/encryption';
import sharp from 'sharp';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

export interface CreateCandidateData {
  electionId: string;
  positionId: string;
  studentId: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  email: string;
  phone: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  manifesto: string;
  slogan?: string;
  photo: string;
  bannerImage?: string;
  runningMateId?: string | null;
  socialMedia?: {
    facebook?: string;
    twitter?: string;
    instagram?: string;
    linkedin?: string;
  };
}

export interface CandidateFilters {
  electionId?: string;
  positionId?: string;
  status?: CandidateStatus;
  faculty?: string;
  department?: string;
  course?: string;
  yearOfStudy?: number;
  search?: string;
}

export interface CandidateStats {
  total: number;
  byStatus: Record<CandidateStatus, number>;
  byFaculty: Record<string, number>;
  byDepartment: Record<string, number>;
  byYear: Record<number, number>;
  totalVotes?: number;
  avgVotes?: number;
  topCandidates?: Array<{
    id: string;
    name: string;
    votes: number;
    position: string;
  }>;
}

export class CandidateService {
  private static instance: CandidateService;
  private static readonly UPLOAD_DIR = 'uploads/candidates';
  private static readonly MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
  private static readonly ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  private static readonly CACHE_TTL = 300; // 5 minutes

  private constructor() {
    // Private constructor for singleton pattern
  }

  public static getInstance(): CandidateService {
    if (!CandidateService.instance) {
      CandidateService.instance = new CandidateService();
    }
    return CandidateService.instance;
  }

  /**
   * Create a new candidate application
   */
  public async createCandidate(
    candidateData: CreateCandidateData,
    submittedBy: string
  ): Promise<Candidate> {
    return await prisma.$transaction(async (tx) => {
      // Validate election exists and is in registration period
      const election = await tx.election.findUnique({
        where: { id: candidateData.electionId },
        include: { positions: true },
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      if (election.status !== 'DRAFT' && election.status !== 'SCHEDULED') {
        throw new AppError('Election is not accepting candidate registrations', 400);
      }

      const now = new Date();
      if (election.registrationEnd && now > election.registrationEnd) {
        throw new AppError('Candidate registration period has ended', 400);
      }

      // Validate position exists
      const position = election.positions.find(p => p.id === candidateData.positionId);
      if (!position) {
        throw new AppError('Position not found in this election', 404);
      }

      // Check if candidate already exists for this position
      const existingCandidate = await tx.candidate.findFirst({
        where: {
          electionId: candidateData.electionId,
          positionId: candidateData.positionId,
          studentId: candidateData.studentId,
        },
      });

      if (existingCandidate) {
        throw new AppError('Student has already registered for this position', 409);
      }

      // Validate student exists and is eligible
      const student = await tx.user.findUnique({
        where: { studentId: candidateData.studentId },
      });

      if (!student) {
        throw new AppError('Student not found in system', 404);
      }

      if (!student.isActive || !student.isVerified) {
        throw new AppError('Student account is not active or verified', 400);
      }

      // Check academic eligibility
      const isEligible = this.checkAcademicEligibility(student, election);
      if (!isEligible) {
        throw new AppError('Student does not meet election eligibility criteria', 400);
      }

      // Validate academic information matches
      if (
        student.faculty !== candidateData.faculty ||
        student.department !== candidateData.department ||
        student.course !== candidateData.course ||
        student.yearOfStudy !== candidateData.yearOfStudy
      ) {
        throw new AppError('Academic information does not match student records', 400);
      }

      // Create candidate
      const { socialMedia, ...restCandidateData } = candidateData;
      const candidate = await tx.candidate.create({
        data: {
          ...restCandidateData,
          socialMedia: socialMedia || {},
          status: 'PENDING',
        },
        include: {
          election: true,
          position: true,
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'CANDIDATE_REGISTRATION',
          category: 'CANDIDATE',
          severity: 'MEDIUM',
          userId: submittedBy,
          entityType: 'Candidate',
          entityId: candidate.id,
          newData: candidateData as any,
        },
      });

      // Clear relevant caches
      await this.clearCandidateCache(candidateData.electionId);

      // Send confirmation email
      await emailService.sendEmail({
        to: candidateData.email,
        subject: `Candidate Application Submitted - ${election.title}`,
        template: 'candidate-application-received',
        data: {
          firstName: candidateData.firstName,
          electionTitle: election.title,
          positionName: position.name,
          applicationId: candidate.id,
        },
      });

      logger.info('Candidate application created', {
        candidateId: candidate.id,
        electionId: candidateData.electionId,
        studentId: candidateData.studentId,
      });

      return candidate;
    });
  }

  /**
   * Update candidate profile
   */
  public async updateCandidateProfile(
    candidateId: string,
    updateData: Partial<CreateCandidateData>,
    updatedBy: string
  ): Promise<Candidate> {
    return await prisma.$transaction(async (tx) => {
      const candidate = await tx.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true },
      });

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Only allow updates if status is PENDING or APPROVED
      if (candidate.status !== 'PENDING' && candidate.status !== 'APPROVED') {
        throw new AppError('Cannot update candidate profile in current status', 400);
      }

      // If election has started, only allow limited updates
      if (candidate.election?.status === 'ACTIVE') {
        const allowedFields = ['manifesto', 'slogan', 'socialMedia'];
        const updateFields = Object.keys(updateData);
        const hasRestrictedUpdates = updateFields.some(field => !allowedFields.includes(field));
        
        if (hasRestrictedUpdates) {
          throw new AppError('Only manifesto, slogan, and social media can be updated during active election', 400);
        }
      }

      const oldData = { ...candidate };
      
      const updatedCandidate = await tx.candidate.update({
        where: { id: candidateId },
        data: {
          ...updateData,
          updatedAt: new Date(),
        },
        include: {
          election: true,
          position: true,
          runningMate: true,
          runningMateFor: true,
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'CANDIDATE_PROFILE_UPDATED',
          category: 'CANDIDATE',
          severity: 'LOW',
          userId: updatedBy,
          entityType: 'Candidate',
          entityId: candidateId,
          oldData,
          newData: updateData,
        },
      });

      // Clear caches
      await this.clearCandidateCache(candidate.electionId);
      await redis.del(`candidate:${candidateId}`);

      logger.info('Candidate profile updated', {
        candidateId,
        updatedBy,
        fields: Object.keys(updateData),
      });

      return updatedCandidate;
    });
  }

  /**
   * Upload and process candidate photo
   */
  public async uploadCandidatePhoto(
    candidateId: string,
    photoBuffer: Buffer,
    originalName: string,
    mimeType: string,
    uploadedBy: string
  ): Promise<{ photoUrl: string }> {
    // Validate file type and size
    if (!CandidateService.ALLOWED_IMAGE_TYPES.includes(mimeType)) {
      throw new ValidationError('Invalid file type. Only JPEG, PNG, and WebP are allowed.');
    }

    if (photoBuffer.length > CandidateService.MAX_FILE_SIZE) {
      throw new ValidationError(`File size too large. Maximum size is ${CandidateService.MAX_FILE_SIZE / 1024 / 1024}MB.`);
    }

    return await prisma.$transaction(async (tx) => {
      const candidate = await tx.candidate.findUnique({
        where: { id: candidateId },
      });

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Create upload directory if it doesn't exist
      const uploadDir = path.join(process.cwd(), CandidateService.UPLOAD_DIR);
      await fs.mkdir(uploadDir, { recursive: true });

      const fileExtension = path.extname(originalName) || '.jpg';
      const fileName = `${candidateId}-${Date.now()}${fileExtension}`;
      const filePath = path.join(uploadDir, fileName);

      // Process image with Sharp
      const processedImage = await sharp(photoBuffer)
        .resize(300, 400, {
          fit: 'cover',
          position: 'center',
        })
        .jpeg({ quality: 85 })
        .toBuffer();

      // Generate thumbnail
      const thumbnailBuffer = await sharp(photoBuffer)
        .resize(150, 200, {
          fit: 'cover',
          position: 'center',
        })
        .jpeg({ quality: 80 })
        .toBuffer();

      const thumbnailFileName = `${candidateId}-thumb-${Date.now()}.jpg`;
      const thumbnailPath = path.join(uploadDir, thumbnailFileName);

      // Save files
      await fs.writeFile(filePath, processedImage);
      await fs.writeFile(thumbnailPath, thumbnailBuffer);

      const photoUrl = `/uploads/candidates/${fileName}`;
      const thumbnailUrl = `/uploads/candidates/${thumbnailFileName}`;

      // Delete old photo if exists
      if (candidate.photo) {
        const oldPhotoPath = path.join(process.cwd(), 'public', candidate.photo);
        await fs.unlink(oldPhotoPath).catch(() => {});
      }

      // Update candidate with new photo URL
      const updatedCandidate = await tx.candidate.update({
        where: { id: candidateId },
        data: { 
          photo: photoUrl,
          // Store thumbnail URL in social media field for now
          socialMedia: {
            ...(candidate.socialMedia as any || {}),
            thumbnail: thumbnailUrl,
          },
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'CANDIDATE_PHOTO_UPLOADED',
          category: 'CANDIDATE',
          severity: 'LOW',
          userId: uploadedBy,
          entityType: 'Candidate',
          entityId: candidateId,
          metadata: {
            originalName,
            fileName,
            fileSize: photoBuffer.length,
          },
        },
      });

      // Clear cache
      await redis.del(`candidate:${candidateId}`);
      await this.clearCandidateCache(candidate.electionId);

      logger.info('Candidate photo uploaded', {
        candidateId,
        fileName,
        fileSize: photoBuffer.length,
      });

      return { photoUrl };
    });
  }

  /**
   * Get candidate by ID
   */
  public async getCandidateById(
    candidateId: string,
    useCache: boolean = true
  ): Promise<Candidate | null> {
    const cacheKey = `candidate:${candidateId}`;

    if (useCache) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const candidate = await prisma.candidate.findUnique({
      where: { id: candidateId },
      include: {
        election: true,
        position: true,
        runningMate: {
          include: {
            election: true,
            position: true,
          },
        },
        runningMateFor: {
          include: {
            election: true,
            position: true,
          },
        },
        votes: {
          select: { id: true },
        },
        results: {
          select: {
            totalVotes: true,
            percentage: true,
            rank: true,
            isWinner: true,
          },
        },
      },
    });

    if (candidate && useCache) {
      await redis.setex(cacheKey, CandidateService.CACHE_TTL, JSON.stringify(candidate));
    }

    return candidate;
  }

  /**
   * Get candidates by election with filtering and pagination
   */
  public async getCandidatesByElection(
    electionId: string,
    filters: CandidateFilters = {},
    page: number = 1,
    limit: number = 50,
    useCache: boolean = true
  ) {
    const cacheKey = `candidates:election:${electionId}:${JSON.stringify({ filters, page, limit })}`;

    if (useCache) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const where: any = { electionId };

    // Apply filters
    if (filters.positionId) where.positionId = filters.positionId;
    if (filters.status) where.status = filters.status;
    if (filters.faculty) where.faculty = filters.faculty;
    if (filters.department) where.department = filters.department;
    if (filters.course) where.course = filters.course;
    if (filters.yearOfStudy) where.yearOfStudy = filters.yearOfStudy;
    
    if (filters.search) {
      where.OR = [
        { firstName: { contains: filters.search, mode: 'insensitive' } },
        { lastName: { contains: filters.search, mode: 'insensitive' } },
        { studentId: { contains: filters.search, mode: 'insensitive' } },
        { manifesto: { contains: filters.search, mode: 'insensitive' } },
      ];
    }

    const [candidates, total] = await Promise.all([
      prisma.candidate.findMany({
        where,
        include: {
          position: true,
          runningMate: true,
          runningMateFor: true,
          votes: { select: { id: true } },
          results: {
            select: {
              totalVotes: true,
              percentage: true,
              rank: true,
              isWinner: true,
            },
          },
        },
        orderBy: [
          { position: { order: 'asc' } },
          { createdAt: 'asc' },
        ],
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.candidate.count({ where }),
    ]);

    const result = {
      candidates,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: limit,
        hasNext: page < Math.ceil(total / limit),
        hasPrevious: page > 1,
      },
    };

    if (useCache) {
      await redis.setex(cacheKey, CandidateService.CACHE_TTL, JSON.stringify(result));
    }

    return result;
  }

  /**
   * Approve candidate application
   */
  public async approveCandidate(
    candidateId: string,
    approvedBy: string,
    reason?: string
  ): Promise<Candidate> {
    return await this.updateCandidateStatus(
      candidateId,
      'APPROVED',
      approvedBy,
      reason
    );
  }

  /**
   * Reject candidate application
   */
  public async rejectCandidate(
    candidateId: string,
    rejectedBy: string,
    reason: string
  ): Promise<Candidate> {
    return await this.updateCandidateStatus(
      candidateId,
      'REJECTED',
      rejectedBy,
      reason
    );
  }

  /**
   * Disqualify candidate
   */
  public async disqualifyCandidate(
    candidateId: string,
    disqualifiedBy: string,
    reason: string
  ): Promise<Candidate> {
    return await this.updateCandidateStatus(
      candidateId,
      'DISQUALIFIED',
      disqualifiedBy,
      reason
    );
  }

  /**
   * Add running mate
   */
  public async addRunningMate(
    candidateId: string,
    runningMateId: string,
    addedBy: string
  ): Promise<Candidate> {
    return await prisma.$transaction(async (tx) => {
      const candidate = await tx.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true },
      });

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      const runningMate = await tx.candidate.findUnique({
        where: { id: runningMateId },
        include: { election: true, position: true },
      });

      if (!runningMate) {
        throw new AppError('Running mate candidate not found', 404);
      }

      // Validate both are in same election
      if (candidate.electionId !== runningMate.electionId) {
        throw new AppError('Candidates must be in the same election', 400);
      }

      // Check if this is a presidential position (assuming it allows running mates)
      if (candidate.election?.type !== 'PRESIDENTIAL') {
        throw new AppError('Running mates are only allowed for presidential positions', 400);
      }

      // Check if candidates are already linked
      if (candidate.runningMateId === runningMateId) {
        throw new AppError('These candidates are already linked as running mates', 400);
      }

      // Update both candidates
      const [updatedCandidate] = await Promise.all([
        tx.candidate.update({
          where: { id: candidateId },
          data: { runningMateId },
          include: {
            election: true,
            position: true,
            runningMate: true,
          },
        }),
        tx.candidate.update({
          where: { id: runningMateId },
          data: { runningMateId: candidateId },
        }),
      ]);

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'RUNNING_MATE_ADDED',
          category: 'CANDIDATE',
          severity: 'MEDIUM',
          userId: addedBy,
          entityType: 'Candidate',
          entityId: candidateId,
          metadata: {
            runningMateId,
            runningMateName: `${runningMate.firstName} ${runningMate.lastName}`,
          },
        },
      });

      // Clear caches
      await this.clearCandidateCache(candidate.electionId);

      // Send notifications
      await Promise.all([
        emailService.sendEmail({
          to: candidate.email,
          subject: 'Running Mate Added',
          template: 'running-mate-added',
          data: {
            candidateName: `${candidate.firstName} ${candidate.lastName}`,
            runningMateName: `${runningMate.firstName} ${runningMate.lastName}`,
            electionTitle: candidate.election?.title,
          },
        }),
        emailService.sendEmail({
          to: runningMate.email,
          subject: 'Added as Running Mate',
          template: 'running-mate-added',
          data: {
            candidateName: `${runningMate.firstName} ${runningMate.lastName}`,
            runningMateName: `${candidate.firstName} ${candidate.lastName}`,
            electionTitle: candidate.election?.title,
          },
        }),
      ]);

      logger.info('Running mate added', {
        candidateId,
        runningMateId,
        addedBy,
      });

      return updatedCandidate;
    });
  }

  /**
   * Get candidate statistics
   */
  public async getCandidateStats(
    electionId: string,
    useCache: boolean = true
  ): Promise<CandidateStats> {
    const cacheKey = `candidate-stats:${electionId}`;

    if (useCache) {
      const cached = await redis.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const [candidates, votes] = await Promise.all([
      prisma.candidate.findMany({
        where: { electionId },
        include: {
          position: true,
          votes: true,
        },
      }),
      prisma.vote.findMany({
        where: { electionId },
        include: {
          candidate: {
            include: { position: true },
          },
        },
      }),
    ]);

    const stats: CandidateStats = {
      total: candidates.length,
      byStatus: {
        PENDING: 0,
        APPROVED: 0,
        REJECTED: 0,
        DISQUALIFIED: 0,
        WITHDRAWN: 0,
      },
      byFaculty: {},
      byDepartment: {},
      byYear: {},
      totalVotes: votes.length,
      avgVotes: votes.length / Math.max(candidates.length, 1),
      topCandidates: [],
    };

    // Calculate statistics
    candidates.forEach(candidate => {
      stats.byStatus[candidate.status]++;
      stats.byFaculty[candidate.faculty] = (stats.byFaculty[candidate.faculty] || 0) + 1;
      stats.byDepartment[candidate.department] = (stats.byDepartment[candidate.department] || 0) + 1;
      stats.byYear[candidate.yearOfStudy] = (stats.byYear[candidate.yearOfStudy] || 0) + 1;
    });

    // Get top candidates by votes
    const candidateVotes = candidates.map(candidate => ({
      id: candidate.id,
      name: `${candidate.firstName} ${candidate.lastName}`,
      votes: candidate.votes.length,
      position: candidate.position?.name || 'Unknown',
    }));

    stats.topCandidates = candidateVotes
      .sort((a, b) => b.votes - a.votes)
      .slice(0, 10);

    if (useCache) {
      await redis.setex(cacheKey, CandidateService.CACHE_TTL, JSON.stringify(stats));
    }

    return stats;
  }

  /**
   * Update candidate status
   */
  public async updateCandidateStatus(
    candidateId: string,
    status: CandidateStatus,
    updatedBy: string,
    reason?: string
  ): Promise<Candidate> {
    return await prisma.$transaction(async (tx) => {
      const candidate = await tx.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true },
      });

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      const oldStatus = candidate.status;
      const now = new Date();

      const updateData: any = {
        status,
        updatedAt: now,
      };

      if (status === 'APPROVED') {
        updateData.verifiedAt = now;
      } else if (status === 'DISQUALIFIED') {
        updateData.disqualifiedAt = now;
        updateData.disqualificationReason = reason;
      }

      const updatedCandidate = await tx.candidate.update({
        where: { id: candidateId },
        data: updateData,
        include: {
          election: true,
          position: true,
          runningMate: true,
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: `CANDIDATE_${status}`,
          category: 'CANDIDATE',
          severity: 'HIGH',
          userId: updatedBy,
          entityType: 'Candidate',
          entityId: candidateId,
          oldData: { status: oldStatus },
          newData: { status, reason },
        },
      });

      // Clear caches
      await this.clearCandidateCache(candidate.electionId);
      await redis.del(`candidate:${candidateId}`);

      // Send notification email
      const emailTemplate = status === 'APPROVED' ? 'candidate-approved' :
                          status === 'REJECTED' ? 'candidate-rejected' :
                          'candidate-disqualified';

      await emailService.sendEmail({
        to: candidate.email,
        subject: `Candidate Application ${status} - ${candidate.election?.title}`,
        template: emailTemplate,
        data: {
          firstName: candidate.firstName,
          electionTitle: candidate.election?.title,
          positionName: candidate.position?.name,
          reason: reason || '',
          status,
        },
      });

      logger.info('Candidate status updated', {
        candidateId,
        oldStatus,
        newStatus: status,
        updatedBy,
        reason,
      });

      return updatedCandidate;
    });
  }

  /**
   * Check academic eligibility
   */
  private checkAcademicEligibility(student: any, election: any): boolean {
    // Check faculty eligibility
    if (election.eligibleFaculties.length > 0 && !election.eligibleFaculties.includes(student.faculty)) {
      return false;
    }

    // Check department eligibility
    if (election.eligibleDepartments.length > 0 && !election.eligibleDepartments.includes(student.department)) {
      return false;
    }

    // Check course eligibility
    if (election.eligibleCourses.length > 0 && !election.eligibleCourses.includes(student.course)) {
      return false;
    }

    // Check year eligibility
    if (election.eligibleYears.length > 0 && !election.eligibleYears.includes(student.yearOfStudy)) {
      return false;
    }

    return true;
  }

  /**
   * Clear candidate-related caches
   */
  private async clearCandidateCache(electionId: string): Promise<void> {
    const pattern = `candidates:election:${electionId}:*`;
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
    }

    await redis.del(`candidate-stats:${electionId}`);
  }

  /**
   * Search candidates across all elections with advanced filtering
   */
  public async searchCandidates(searchParams: {
    search?: string;
    status?: string;
    faculty?: string;
    department?: string;
    course?: string;
    yearOfStudy?: number;
    electionId?: string;
    page: number;
    limit: number;
    sortBy: string;
    sortOrder: 'asc' | 'desc';
  }) {
    const { search, status, faculty, department, course, yearOfStudy, electionId, page, limit, sortBy, sortOrder } = searchParams;

    const where: any = {};

    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { studentId: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
        { manifesto: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (status) where.status = status;
    if (faculty) where.faculty = faculty;
    if (department) where.department = department;
    if (course) where.course = course;
    if (yearOfStudy) where.yearOfStudy = yearOfStudy;
    if (electionId) where.electionId = electionId;

    const [candidates, total] = await Promise.all([
      prisma.candidate.findMany({
        where,
        include: {
          election: true,
          position: true,
          runningMate: true,
          votes: { select: { id: true } },
          results: {
            select: {
              totalVotes: true,
              percentage: true,
              rank: true,
              isWinner: true,
            },
          },
        },
        orderBy: { [sortBy]: sortOrder },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.candidate.count({ where }),
    ]);

    return {
      candidates,
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
   * Export candidates data in various formats
   */
  public async exportCandidates(exportParams: {
    electionId: string;
    format: string;
    status?: string;
    includePersonalData: boolean;
    includeManifestos: boolean;
    exportedBy: string;
  }) {
    const { electionId, format, status, includePersonalData, includeManifestos } = exportParams;

    const where: any = { electionId };
    if (status) where.status = status;

    const candidates = await prisma.candidate.findMany({
      where,
      include: {
        election: true,
        position: true,
        votes: { select: { id: true } },
        results: {
          select: {
            totalVotes: true,
            percentage: true,
            rank: true,
            isWinner: true,
          },
        },
      },
      orderBy: [
        { position: { order: 'asc' } },
        { createdAt: 'asc' },
      ],
    });

    // Format data based on requirements
    const exportData = candidates.map(candidate => {
      const data: any = {
        id: candidate.id,
        studentId: includePersonalData ? candidate.studentId : '***REDACTED***',
        firstName: candidate.firstName,
        lastName: candidate.lastName,
        position: candidate.position?.name,
        status: candidate.status,
        faculty: candidate.faculty,
        department: candidate.department,
        course: candidate.course,
        yearOfStudy: candidate.yearOfStudy,
        totalVotes: candidate.votes.length,
        createdAt: candidate.createdAt,
      };

      if (includePersonalData) {
        data.email = candidate.email;
        data.phone = candidate.phone;
      }

      if (includeManifestos) {
        data.manifesto = candidate.manifesto;
        data.slogan = candidate.slogan;
      }

      if (candidate.results && candidate.results.length > 0) {
        data.rank = candidate.results[0].rank;
        data.percentage = candidate.results[0].percentage;
        data.isWinner = candidate.results[0].isWinner;
      }

      return data;
    });

    if (format === 'json') {
      return {
        data: exportData,
        filename: `candidates-${electionId}-${Date.now()}.json`,
        mimeType: 'application/json',
        recordCount: exportData.length,
      };
    }

    // For CSV format
    const csv = this.convertToCSV(exportData);
    return {
      buffer: Buffer.from(csv),
      filename: `candidates-${electionId}-${Date.now()}.csv`,
      mimeType: 'text/csv',
      recordCount: exportData.length,
    };
  }

  /**
   * Bulk approve candidates
   */
  public async bulkApproveCandidates(bulkParams: {
    candidateIds: string[];
    reason?: string;
    approvedBy: string;
  }) {
    const { candidateIds, reason, approvedBy } = bulkParams;

    const successful: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    await Promise.allSettled(
      candidateIds.map(async (candidateId) => {
        try {
          await this.approveCandidate(candidateId, approvedBy, reason);
          successful.push(candidateId);
        } catch (error) {
          failed.push({
            id: candidateId,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      })
    );

    return {
      successful: successful.length,
      failed: failed.length,
      details: { successful, failed },
    };
  }

  /**
   * Bulk reject candidates
   */
  public async bulkRejectCandidates(bulkParams: {
    candidateIds: string[];
    reason: string;
    rejectedBy: string;
  }) {
    const { candidateIds, reason, rejectedBy } = bulkParams;

    const successful: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    await Promise.allSettled(
      candidateIds.map(async (candidateId) => {
        try {
          await this.rejectCandidate(candidateId, rejectedBy, reason);
          successful.push(candidateId);
        } catch (error) {
          failed.push({
            id: candidateId,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      })
    );

    return {
      successful: successful.length,
      failed: failed.length,
      details: { successful, failed },
    };
  }

  /**
   * Get comprehensive candidate analytics
   */
  public async getCandidateAnalytics(electionId: string, options: {
    includeVoteAnalysis: boolean;
    includeDemographics: boolean;
    includePerformanceMetrics: boolean;
  }) {
    const candidates = await prisma.candidate.findMany({
      where: { electionId },
      include: {
        position: true,
        votes: true,
        results: true,
      },
    });

    const analytics: any = {
      summary: {
        totalCandidates: candidates.length,
        byStatus: this.groupBy(candidates, 'status'),
        byPosition: this.groupBy(candidates, c => c.position?.name || 'Unknown'),
      },
    };

    if (options.includeDemographics) {
      analytics.demographics = {
        byFaculty: this.groupBy(candidates, 'faculty'),
        byDepartment: this.groupBy(candidates, 'department'),
        byCourse: this.groupBy(candidates, 'course'),
        byYear: this.groupBy(candidates, 'yearOfStudy'),
      };
    }

    if (options.includeVoteAnalysis) {
      analytics.voteAnalysis = {
        totalVotes: candidates.reduce((sum, c) => sum + c.votes.length, 0),
        averageVotesPerCandidate: candidates.reduce((sum, c) => sum + c.votes.length, 0) / candidates.length,
        topPerformers: candidates
          .map(c => ({
            id: c.id,
            name: `${c.firstName} ${c.lastName}`,
            position: c.position?.name,
            votes: c.votes.length,
            percentage: (c.results && c.results.length > 0) ? c.results[0].percentage : 0,
          }))
          .sort((a, b) => b.votes - a.votes)
          .slice(0, 10),
      };
    }

    if (options.includePerformanceMetrics) {
      analytics.performanceMetrics = {
        competitionRates: this.calculateCompetitionRates(candidates),
        winnersByPosition: candidates
          .filter(c => c.results && c.results.length > 0 && c.results[0].isWinner)
          .map(c => ({
            id: c.id,
            name: `${c.firstName} ${c.lastName}`,
            position: c.position?.name,
            votes: c.votes.length,
            percentage: (c.results && c.results.length > 0) ? c.results[0].percentage : 0,
          })),
      };
    }

    return analytics;
  }

  /**
   * Helper method to group candidates by a property
   */
  private groupBy(candidates: any[], property: string | ((item: any) => string)): Record<string, number> {
    const result: Record<string, number> = {};

    candidates.forEach(candidate => {
      const key = typeof property === 'function' ? property(candidate) : candidate[property];
      result[key] = (result[key] || 0) + 1;
    });

    return result;
  }

  /**
   * Calculate competition rates by position
   */
  private calculateCompetitionRates(candidates: any[]) {
    const byPosition = this.groupBy(candidates, c => c.position?.name || 'Unknown');
    const rates: Record<string, number> = {};

    Object.entries(byPosition).forEach(([position, count]) => {
      rates[position] = count; // Competition rate = number of candidates for position
    });

    return rates;
  }

  /**
   * Convert array of objects to CSV format
   */
  private convertToCSV(data: any[]): string {
    if (data.length === 0) return '';

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row =>
        headers.map(header => {
          const value = row[header];
          // Escape commas and quotes in CSV
          if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
            return `"${value.replace(/"/g, '""')}"`;
          }
          return value;
        }).join(',')
      )
    ];

    return csvContent.join('\n');
  }
}

export default CandidateService;