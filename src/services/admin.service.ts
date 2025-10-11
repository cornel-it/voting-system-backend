import { PrismaClient, User, UserRole, Election, AuditLog } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger, logAudit } from '../utils/logger';
import { AppError, ValidationError } from '../utils/errors';
import { HashingService } from '../utils/hashing';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { encryptionService } from '../utils/encryption';
import * as XLSX from 'xlsx';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface SystemStats {
  totalUsers: number;
  activeUsers: number;
  totalElections: number;
  activeElections: number;
  completedElections: number;
  totalVotes: number;
  totalCandidates: number;
  approvedCandidates: number;
  systemHealth: {
    database: boolean;
    redis: boolean;
    email: boolean;
    sms: boolean;
  };
  recentActivity: {
    newUsersToday: number;
    votesToday: number;
    newElectionsThisWeek: number;
  };
}

export interface UserImportData {
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
}

export interface UserImportResult {
  totalProcessed: number;
  successful: number;
  failed: number;
  duplicates: number;
  errors: Array<{
    row: number;
    studentId: string;
    error: string;
  }>;
}

export interface AdminActivity {
  id: string;
  adminId: string;
  adminName: string;
  action: string;
  category: string;
  severity: string;
  targetEntity?: string;
  targetId?: string;
  timestamp: Date;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
}

export class AdminService {
  private static readonly CACHE_TTL = 300; // 5 minutes
  private static readonly BATCH_SIZE = 100;

  /**
   * Get system statistics
   */
  public static async getSystemStats(): Promise<SystemStats> {
    const cacheKey = 'admin:system-stats';
    const cached = await redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const today = new Date();
    const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    const weekStart = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);

    const [stats, recentActivity, systemHealth] = await Promise.all([
      // Basic counts
      Promise.all([
        prisma.user.count(),
        prisma.user.count({ where: { isActive: true } }),
        prisma.election.count(),
        prisma.election.count({ where: { status: 'ACTIVE' } }),
        prisma.election.count({ where: { status: 'COMPLETED' } }),
        prisma.vote.count(),
        prisma.candidate.count(),
        prisma.candidate.count({ where: { status: 'APPROVED' } }),
      ]),
      // Recent activity
      Promise.all([
        prisma.user.count({ where: { createdAt: { gte: todayStart } } }),
        prisma.vote.count({ where: { castAt: { gte: todayStart } } }),
        prisma.election.count({ where: { createdAt: { gte: weekStart } } }),
      ]),
      // System health checks
      this.checkSystemHealth(),
    ]);

    const systemStats: SystemStats = {
      totalUsers: stats[0],
      activeUsers: stats[1],
      totalElections: stats[2],
      activeElections: stats[3],
      completedElections: stats[4],
      totalVotes: stats[5],
      totalCandidates: stats[6],
      approvedCandidates: stats[7],
      systemHealth,
      recentActivity: {
        newUsersToday: recentActivity[0],
        votesToday: recentActivity[1],
        newElectionsThisWeek: recentActivity[2],
      },
    };

    // Cache for 5 minutes
    await redis.setex(cacheKey, this.CACHE_TTL, JSON.stringify(systemStats));

    return systemStats;
  }

  /**
   * Create admin user
   */
  public static async createAdminUser(
    userData: {
      studentId: string;
      email: string;
      firstName: string;
      lastName: string;
      middleName?: string;
      phone?: string;
      role: UserRole;
      permissions?: string[];
    },
    createdBy: string
  ): Promise<User> {
    return await prisma.$transaction(async (tx) => {
      // Check if user already exists
      const existingUser = await tx.user.findFirst({
        where: {
          OR: [
            { email: userData.email },
            { studentId: userData.studentId },
          ],
        },
      });

      if (existingUser) {
        throw new AppError('User with this email or student ID already exists', 409);
      }

      // Generate temporary password
      const tempPassword = encryptionService.generateToken(12);
      const hashedPassword = await HashingService.hashPassword(tempPassword);

      // Create user
      const user = await tx.user.create({
        data: {
          ...userData,
          password: hashedPassword,
          isActive: true,
          isVerified: true,
          emailVerified: new Date(),
          // Set default academic info for admin users
          faculty: 'Administration',
          department: 'ICT',
          course: 'Administration',
          yearOfStudy: 1,
          admissionYear: new Date().getFullYear(),
          permissions: userData.permissions || [],
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'ADMIN_USER_CREATED',
          category: 'USER',
          severity: 'HIGH',
          userId: createdBy,
          entityType: 'User',
          entityId: user.id,
          newData: {
            studentId: userData.studentId,
            email: userData.email,
            role: userData.role,
          },
        },
      });

      // Send welcome email with temporary password
      await emailService.sendEmail({
        to: userData.email,
        subject: 'Admin Account Created - JKUAT Voting System',
        template: 'admin-welcome',
        data: {
          firstName: userData.firstName,
          tempPassword,
          loginUrl: `${process.env.FRONTEND_URL}/login`,
          role: userData.role,
        },
      });

      logger.info('Admin user created', {
        adminId: user.id,
        createdBy,
        role: userData.role,
      });

      return user;
    });
  }

  /**
   * Update user role and permissions
   */
  public static async updateUserRole(
    userId: string,
    role: UserRole,
    permissions: string[],
    updatedBy: string
  ): Promise<User> {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const oldData = {
        role: user.role,
        permissions: user.permissions,
      };

      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: {
          role,
          permissions,
          updatedAt: new Date(),
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: 'USER_ROLE_UPDATED',
          category: 'USER',
          severity: 'HIGH',
          userId: updatedBy,
          entityType: 'User',
          entityId: userId,
          oldData,
          newData: { role, permissions },
        },
      });

      // Send notification email
      await emailService.sendEmail({
        to: user.email,
        subject: 'Account Permissions Updated - JKUAT Voting System',
        template: 'role-updated',
        data: {
          firstName: user.firstName,
          oldRole: oldData.role,
          newRole: role,
          permissions,
        },
      });

      logger.info('User role updated', {
        userId,
        oldRole: oldData.role,
        newRole: role,
        updatedBy,
      });

      return updatedUser;
    });
  }

  /**
   * Bulk import users from Excel file
   */
  public static async importUsersFromExcel(
    fileBuffer: Buffer,
    filename: string,
    importedBy: string
  ): Promise<UserImportResult> {
    const result: UserImportResult = {
      totalProcessed: 0,
      successful: 0,
      failed: 0,
      duplicates: 0,
      errors: [],
    };

    try {
      // Parse Excel file
      const workbook = XLSX.read(fileBuffer, { type: 'buffer' });
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];
      const data = XLSX.utils.sheet_to_json(worksheet) as any[];

      result.totalProcessed = data.length;

      // Process in batches
      for (let i = 0; i < data.length; i += this.BATCH_SIZE) {
        const batch = data.slice(i, i + this.BATCH_SIZE);
        
        await Promise.all(
          batch.map(async (row, index) => {
            const rowNumber = i + index + 2; // +2 for header and 1-based indexing
            
            try {
              // Validate required fields
              const userData = this.validateUserImportRow(row);
              
              // Check for existing user
              const existingUser = await prisma.user.findFirst({
                where: {
                  OR: [
                    { email: userData.email },
                    { studentId: userData.studentId },
                  ],
                },
              });

              if (existingUser) {
                result.duplicates++;
                return;
              }

              // Generate password and hash it
              const tempPassword = encryptionService.generateToken(8);
              const hashedPassword = await HashingService.hashPassword(tempPassword);

              // Create user
              await prisma.user.create({
                data: {
                  ...userData,
                  password: hashedPassword,
                  role: 'VOTER',
                  isActive: true,
                  isVerified: false,
                  permissions: [],
                },
              });

              // Send welcome email (in background)
              emailService.sendWelcomeEmail({
                email: userData.email,
                firstName: userData.firstName,
                studentId: userData.studentId,
              }).catch(error => {
                logger.warn('Failed to send welcome email', {
                  email: userData.email,
                  error: error.message,
                });
              });

              result.successful++;
            } catch (error: any) {
              result.failed++;
              result.errors.push({
                row: rowNumber,
                studentId: row.studentId || 'Unknown',
                error: error.message,
              });
            }
          })
        );
      }

      // Create audit log
      await prisma.auditLog.create({
        data: {
          action: 'BULK_USER_IMPORT',
          category: 'USER',
          severity: 'MEDIUM',
          userId: importedBy,
          metadata: {
            filename,
            ...result,
          },
        },
      });

      logger.info('Bulk user import completed', {
        filename,
        importedBy,
        ...result,
      });

      return result;
    } catch (error: any) {
      logger.error('Bulk user import failed', {
        filename,
        importedBy,
        error: error.message,
      });
      throw new AppError('Failed to import users: ' + error.message, 400);
    }
  }

  /**
   * Get system audit logs
   */
  public static async getAuditLogs(
    filters: {
      userId?: string;
      category?: string;
      severity?: string;
      startDate?: Date;
      endDate?: Date;
      search?: string;
    } = {},
    page: number = 1,
    limit: number = 50
  ) {
    const where: any = {};

    if (filters.userId) where.userId = filters.userId;
    if (filters.category) where.category = filters.category;
    if (filters.severity) where.severity = filters.severity;
    
    if (filters.startDate || filters.endDate) {
      where.createdAt = {};
      if (filters.startDate) where.createdAt.gte = filters.startDate;
      if (filters.endDate) where.createdAt.lte = filters.endDate;
    }

    if (filters.search) {
      where.OR = [
        { action: { contains: filters.search, mode: 'insensitive' } },
        { entityType: { contains: filters.search, mode: 'insensitive' } },
        { entityId: { contains: filters.search, mode: 'insensitive' } },
      ];
    }

    const [auditLogs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
              role: true,
            },
          },
          election: {
            select: {
              id: true,
              title: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.auditLog.count({ where }),
    ]);

    return {
      auditLogs: auditLogs.map(log => ({
        id: log.id,
        adminId: log.userId,
        adminName: log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System',
        action: log.action,
        category: log.category,
        severity: log.severity,
        targetEntity: log.entityType,
        targetId: log.entityId,
        timestamp: log.createdAt,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        metadata: log.metadata,
      })) as AdminActivity[],
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
   * Activate/Deactivate user account
   */
  public static async toggleUserStatus(
    userId: string,
    isActive: boolean,
    actionBy: string,
    reason?: string
  ): Promise<User> {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: {
          isActive,
          updatedAt: new Date(),
        },
      });

      // Create audit log
      await tx.auditLog.create({
        data: {
          action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
          category: 'USER',
          severity: 'HIGH',
          userId: actionBy,
          entityType: 'User',
          entityId: userId,
          metadata: { reason },
        },
      });

      // Send notification
      await emailService.sendEmail({
        to: user.email,
        subject: `Account ${isActive ? 'Activated' : 'Deactivated'} - JKUAT Voting System`,
        template: 'account-status-changed',
        data: {
          firstName: user.firstName,
          isActive,
          reason: reason || 'Administrative decision',
        },
      });

      logger.info('User status updated', {
        userId,
        isActive,
        actionBy,
        reason,
      });

      return updatedUser;
    });
  }

  /**
   * Generate system report
   */
  public static async generateSystemReport(
    reportType: 'users' | 'elections' | 'votes' | 'audit',
    filters: any = {},
    format: 'json' | 'excel' = 'json'
  ): Promise<any> {
    let data: any[];
    let headers: string[];

    switch (reportType) {
      case 'users':
        data = await prisma.user.findMany({
          where: filters,
          select: {
            studentId: true,
            email: true,
            firstName: true,
            lastName: true,
            faculty: true,
            department: true,
            course: true,
            yearOfStudy: true,
            role: true,
            isActive: true,
            isVerified: true,
            createdAt: true,
            lastLogin: true,
          },
        });
        headers = ['Student ID', 'Email', 'First Name', 'Last Name', 'Faculty', 'Department', 'Course', 'Year', 'Role', 'Active', 'Verified', 'Created', 'Last Login'];
        break;

      case 'elections':
        data = await prisma.election.findMany({
          where: filters,
          include: {
            createdBy: {
              select: { firstName: true, lastName: true },
            },
            _count: {
              select: {
                candidates: true,
                votes: true,
              },
            },
          },
        });
        headers = ['Title', 'Type', 'Status', 'Start Date', 'End Date', 'Total Votes', 'Candidates', 'Created By', 'Created At'];
        break;

      case 'votes':
        data = await prisma.vote.findMany({
          where: filters,
          include: {
            election: { select: { title: true } },
            position: { select: { name: true } },
            candidate: { select: { firstName: true, lastName: true } },
            voter: { select: { faculty: true, department: true, yearOfStudy: true } },
          },
        });
        headers = ['Election', 'Position', 'Candidate', 'Voter Faculty', 'Voter Department', 'Voter Year', 'Cast At', 'Verified'];
        break;

      case 'audit':
        data = await prisma.auditLog.findMany({
          where: filters,
          include: {
            user: { select: { firstName: true, lastName: true } },
          },
          orderBy: { createdAt: 'desc' },
        });
        headers = ['Action', 'Category', 'Severity', 'User', 'Entity Type', 'Entity ID', 'Timestamp', 'IP Address'];
        break;

      default:
        throw new AppError('Invalid report type', 400);
    }

    if (format === 'excel') {
      // Convert data to Excel format
      const worksheet = XLSX.utils.json_to_sheet(data);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, reportType);
      
      return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
    }

    return { data, headers, total: data.length };
  }

  /**
   * Clear system caches
   */
  public static async clearSystemCaches(
    cacheType: 'all' | 'users' | 'elections' | 'results' | 'stats',
    clearedBy: string
  ): Promise<{ cleared: number }> {
    let patterns: string[] = [];

    switch (cacheType) {
      case 'all':
        patterns = ['*'];
        break;
      case 'users':
        patterns = ['user:*', 'users:*'];
        break;
      case 'elections':
        patterns = ['election:*', 'elections:*', 'candidates:*'];
        break;
      case 'results':
        patterns = ['election-results:*', 'voting-analytics:*', 'live-stats:*'];
        break;
      case 'stats':
        patterns = ['admin:*', 'candidate-stats:*'];
        break;
    }

    let totalCleared = 0;
    for (const pattern of patterns) {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
        totalCleared += keys.length;
      }
    }

    // Create audit log
    await prisma.auditLog.create({
      data: {
        action: 'SYSTEM_CACHE_CLEARED',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId: clearedBy,
        metadata: {
          cacheType,
          keysCleared: totalCleared,
        },
      },
    });

    logger.info('System caches cleared', {
      cacheType,
      keysCleared: totalCleared,
      clearedBy,
    });

    return { cleared: totalCleared };
  }

  /**
   * Get system health status (public method for controller)
   */
  public static async getSystemHealth(): Promise<SystemStats['systemHealth']> {
    return await this.checkSystemHealth();
  }

  /**
   * Initiate database backup
   */
  public static async initiateBackup(options: {
    includePersonalData: boolean;
    initiatedBy: string;
  }): Promise<{ id: string; status: string; timestamp: Date }> {
    const backupId = encryptionService.generateToken(16);

    logger.info('Database backup initiated', {
      backupId,
      includePersonalData: options.includePersonalData,
      initiatedBy: options.initiatedBy,
    });

    // In a real implementation, this would trigger actual backup process
    // For now, we'll return a mock response
    return {
      id: backupId,
      status: 'initiated',
      timestamp: new Date(),
    };
  }

  /**
   * Initiate emergency shutdown
   */
  public static async initiateEmergencyShutdown(options: {
    reason: string;
    duration?: number;
    initiatedBy: string;
  }): Promise<{ id: string; status: string; scheduledAt: Date }> {
    const shutdownId = encryptionService.generateToken(16);

    logger.error('Emergency shutdown initiated', {
      shutdownId,
      reason: options.reason,
      duration: options.duration,
      initiatedBy: options.initiatedBy,
    });

    // In a real implementation, this would trigger shutdown procedures
    // For now, we'll return a mock response
    return {
      id: shutdownId,
      status: 'scheduled',
      scheduledAt: new Date(),
    };
  }

  /**
   * Check system health (private method)
   */
  private static async checkSystemHealth(): Promise<SystemStats['systemHealth']> {
    const health = {
      database: false,
      redis: false,
      email: false,
      sms: false,
    };

    try {
      // Test database
      await prisma.$queryRaw`SELECT 1`;
      health.database = true;
    } catch (error) {
      logger.error('Database health check failed', error);
    }

    try {
      // Test Redis
      await redis.ping();
      health.redis = true;
    } catch (error) {
      logger.error('Redis health check failed', error);
    }

    try {
      // Test email service (simplified check)
      health.email = !!process.env.SENDGRID_API_KEY;
    } catch (error) {
      logger.error('Email health check failed', error);
    }

    try {
      // Test SMS service (simplified check)
      health.sms = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN);
    } catch (error) {
      logger.error('SMS health check failed', error);
    }

    return health;
  }

  /**
   * Validate user import row (private method)
   */
  private static validateUserImportRow(row: any): UserImportData {
    const requiredFields = [
      'studentId', 'email', 'firstName', 'lastName',
      'faculty', 'department', 'course', 'yearOfStudy', 'admissionYear'
    ];

    for (const field of requiredFields) {
      if (!row[field]) {
        throw new ValidationError(`Missing required field: ${field}`);
      }
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(row.email)) {
      throw new ValidationError('Invalid email format');
    }

    // Validate student ID format
    const studentIdRegex = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
    if (!studentIdRegex.test(row.studentId)) {
      throw new ValidationError('Invalid student ID format');
    }

    // Validate numeric fields
    const yearOfStudy = parseInt(row.yearOfStudy);
    const admissionYear = parseInt(row.admissionYear);
    
    if (isNaN(yearOfStudy) || yearOfStudy < 1 || yearOfStudy > 6) {
      throw new ValidationError('Invalid year of study (must be 1-6)');
    }

    if (isNaN(admissionYear) || admissionYear < 2000 || admissionYear > new Date().getFullYear()) {
      throw new ValidationError('Invalid admission year');
    }

    return {
      studentId: row.studentId.trim(),
      email: row.email.toLowerCase().trim(),
      firstName: row.firstName.trim(),
      lastName: row.lastName.trim(),
      middleName: row.middleName?.trim(),
      phone: row.phone?.trim(),
      faculty: row.faculty.trim(),
      department: row.department.trim(),
      course: row.course.trim(),
      yearOfStudy,
      admissionYear,
    };
  }
}

export default AdminService;