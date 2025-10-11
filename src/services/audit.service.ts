import { PrismaClient, AuditLog, UserRole, ElectionStatus } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger } from '../utils/logger';
import { AppError, ValidationError } from '../utils/errors';
import { encryptionService } from '../utils/encryption';
import * as XLSX from 'xlsx';
import * as fs from 'fs/promises';

export interface AuditLogEntry {
  id: string;
  action: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  userId?: string;
  userName?: string;
  userRole?: UserRole;
  entityType?: string;
  entityId?: string;
  electionId?: string;
  electionTitle?: string;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  oldData?: any;
  newData?: any;
  metadata?: any;
  timestamp: Date;
  location?: string;
  deviceInfo?: any;
  risk?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  flags?: string[];
}

export interface AuditFilters {
  userId?: string;
  userRole?: UserRole;
  category?: string;
  action?: string;
  severity?: string;
  entityType?: string;
  entityId?: string;
  electionId?: string;
  startDate?: Date;
  endDate?: Date;
  ipAddress?: string;
  search?: string;
  risk?: string;
  flags?: string[];
}

export interface SecurityEvent {
  id: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
  timestamp: Date;
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: Date;
}

export interface ComplianceReport {
  period: { start: Date; end: Date };
  summary: {
    totalActions: number;
    userActions: number;
    adminActions: number;
    systemActions: number;
    securityEvents: number;
    dataChanges: number;
    accessAttempts: number;
  };
  categorizedActivity: Array<{
    category: string;
    count: number;
    percentage: number;
  }>;
  riskAssessment: {
    highRiskActions: number;
    suspiciousPatterns: number;
    failedAttempts: number;
    unusualActivity: number;
  };
  userActivity: Array<{
    userId: string;
    userName: string;
    role: UserRole;
    actionCount: number;
    lastActivity: Date;
    riskScore: number;
  }>;
  electionActivity: Array<{
    electionId: string;
    electionTitle: string;
    actionCount: number;
    voterActivity: number;
    adminActivity: number;
    lastActivity: Date;
  }>;
  systemMetrics: {
    averageResponseTime: number;
    errorRate: number;
    uptimePercentage: number;
    securityIncidents: number;
  };
}

export interface AuditAnalytics {
  timeRange: { start: Date; end: Date };
  activityTrends: Array<{
    date: string;
    count: number;
    userActions: number;
    adminActions: number;
    systemActions: number;
  }>;
  userBehaviorAnalysis: {
    mostActiveUsers: Array<{
      userId: string;
      userName: string;
      actionCount: number;
    }>;
    suspiciousActivity: Array<{
      userId: string;
      userName: string;
      riskScore: number;
      reason: string;
    }>;
    accessPatterns: Array<{
      hour: number;
      count: number;
    }>;
  };
  securityAnalysis: {
    failedLogins: number;
    suspiciousIPs: Array<{
      ip: string;
      attempts: number;
      lastSeen: Date;
    }>;
    anomalies: Array<{
      type: string;
      description: string;
      severity: string;
      timestamp: Date;
    }>;
  };
  dataIntegrity: {
    totalChecks: number;
    passedChecks: number;
    failedChecks: number;
    lastCheck: Date;
  };
}

export class AuditService {
  private static readonly CACHE_TTL = 300; // 5 minutes
  private static readonly BATCH_SIZE = 1000;
  private static readonly RETENTION_DAYS = 2555; // 7 years for compliance

  /**
   * Create an audit log entry
   */
  public static async logAction(data: {
    action: string;
    category: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    userId?: string;
    entityType?: string;
    entityId?: string;
    electionId?: string;
    oldData?: any;
    newData?: any;
    metadata?: any;
    ipAddress?: string;
    userAgent?: string;
    sessionId?: string;
    location?: string;
    deviceInfo?: any;
  }): Promise<AuditLog> {
    try {
      // Generate unique ID for this audit entry
      const auditId = encryptionService.generateToken(16);

      // Analyze risk level
      const riskLevel = this.assessRiskLevel(data);

      // Detect any suspicious patterns
      const flags = await this.detectSuspiciousPatterns(data);

      const auditEntry = await prisma.auditLog.create({
        data: {
          id: auditId,
          action: data.action,
          category: data.category as any,
          severity: data.severity,
          userId: data.userId,
          entityType: data.entityType,
          entityId: data.entityId,
          electionId: data.electionId,
          oldData: data.oldData,
          newData: data.newData,
          metadata: {
            ...data.metadata,
            risk: riskLevel,
            flags,
            location: data.location,
            deviceInfo: data.deviceInfo,
            sessionId: data.sessionId,
          },
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
        },
      });

      // Log to external audit system if required
      if (data.severity === 'HIGH' || data.severity === 'CRITICAL') {
        await this.logToExternalAuditSystem(auditEntry);
      }

      // Real-time alerts for critical events
      if (data.severity === 'CRITICAL' || riskLevel === 'CRITICAL') {
        await this.triggerSecurityAlert(auditEntry);
      }

      logger.info('Audit log created', {
        auditId,
        action: data.action,
        userId: data.userId,
        severity: data.severity,
      });

      return auditEntry;
    } catch (error) {
      logger.error('Error creating audit log:', error);
      throw new AppError('Failed to create audit log', 500);
    }
  }

  /**
   * Get audit logs with advanced filtering
   */
  public static async getAuditLogs(
    filters: AuditFilters = {},
    page: number = 1,
    limit: number = 50,
    sortBy: string = 'createdAt',
    sortOrder: 'asc' | 'desc' = 'desc'
  ) {
    try {
      const where: any = {};

      // Apply filters
      if (filters.userId) where.userId = filters.userId;
      if (filters.category) where.category = filters.category;
      if (filters.action) where.action = filters.action;
      if (filters.severity) where.severity = filters.severity;
      if (filters.entityType) where.entityType = filters.entityType;
      if (filters.entityId) where.entityId = filters.entityId;
      if (filters.electionId) where.electionId = filters.electionId;
      if (filters.ipAddress) where.ipAddress = filters.ipAddress;

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
          { metadata: { path: ['description'], string_contains: filters.search } },
        ];
      }

      if (filters.risk) {
        where.metadata = {
          path: ['risk'],
          equals: filters.risk,
        };
      }

      if (filters.flags && filters.flags.length > 0) {
        where.metadata = {
          path: ['flags'],
          array_contains: filters.flags,
        };
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
                studentId: true,
              },
            },
            election: {
              select: {
                id: true,
                title: true,
                type: true,
                status: true,
              },
            },
          },
          orderBy: { [sortBy]: sortOrder },
          skip: (page - 1) * limit,
          take: limit,
        }),
        prisma.auditLog.count({ where }),
      ]);

      const enrichedLogs = auditLogs.map(log => this.enrichAuditLog(log));

      return {
        auditLogs: enrichedLogs,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit,
          hasNext: page < Math.ceil(total / limit),
          hasPrevious: page > 1,
        },
        summary: {
          totalLogs: total,
          criticalEvents: auditLogs.filter(log => log.severity === 'CRITICAL').length,
          highRiskEvents: auditLogs.filter(log => (log.metadata as any)?.risk === 'HIGH').length,
          suspiciousEvents: auditLogs.filter(log => (log.metadata as any)?.flags?.length > 0).length,
        },
      };
    } catch (error) {
      logger.error('Error fetching audit logs:', error);
      throw new AppError('Failed to fetch audit logs', 500);
    }
  }

  /**
   * Get security events
   */
  public static async getSecurityEvents(
    filters: any = {},
    page: number = 1,
    limit: number = 20
  ): Promise<{ events: SecurityEvent[]; pagination: any }> {
    try {
      const where: any = {
        OR: [
          { severity: { in: ['HIGH', 'CRITICAL'] } },
          { metadata: { path: ['flags'], not: { equals: [] } } },
          { action: { contains: 'FAILED' } },
          { action: { contains: 'SUSPICIOUS' } },
          { action: { contains: 'BLOCKED' } },
        ],
      };

      if (filters.resolved !== undefined) {
        where.metadata = {
          ...where.metadata,
          path: ['resolved'],
          equals: filters.resolved,
        };
      }

      const [events, total] = await Promise.all([
        prisma.auditLog.findMany({
          where,
          orderBy: { createdAt: 'desc' },
          skip: (page - 1) * limit,
          take: limit,
          include: {
            user: {
              select: {
                firstName: true,
                lastName: true,
                email: true,
              },
            },
          },
        }),
        prisma.auditLog.count({ where }),
      ]);

      const securityEvents: SecurityEvent[] = events.map(event => ({
        id: event.id,
        type: event.action,
        severity: event.severity as any,
        description: this.generateSecurityEventDescription(event),
        userId: event.userId || undefined,
        ipAddress: event.ipAddress || undefined,
        userAgent: event.userAgent || undefined,
        metadata: event.metadata,
        timestamp: event.createdAt,
        resolved: (event.metadata as any)?.resolved || false,
        resolvedBy: (event.metadata as any)?.resolvedBy,
        resolvedAt: (event.metadata as any)?.resolvedAt ? new Date((event.metadata as any).resolvedAt) : undefined,
      }));

      return {
        events: securityEvents,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          itemsPerPage: limit,
        },
      };
    } catch (error) {
      logger.error('Error fetching security events:', error);
      throw new AppError('Failed to fetch security events', 500);
    }
  }

  /**
   * Generate compliance report
   */
  public static async generateComplianceReport(
    startDate: Date,
    endDate: Date
  ): Promise<ComplianceReport> {
    try {
      const cacheKey = `compliance-report:${startDate.getTime()}-${endDate.getTime()}`;
      const cached = await redis.get(cacheKey);

      if (cached) {
        return JSON.parse(cached);
      }

      const [
        totalActions,
        categorizedActivity,
        userActivity,
        electionActivity,
        securityMetrics,
      ] = await Promise.all([
        this.getTotalActionsInPeriod(startDate, endDate),
        this.getCategorizedActivity(startDate, endDate),
        this.getUserActivitySummary(startDate, endDate),
        this.getElectionActivitySummary(startDate, endDate),
        this.getSecurityMetrics(startDate, endDate),
      ]);

      const report: ComplianceReport = {
        period: { start: startDate, end: endDate },
        summary: totalActions,
        categorizedActivity,
        riskAssessment: securityMetrics.riskAssessment,
        userActivity,
        electionActivity,
        systemMetrics: securityMetrics.systemMetrics,
      };

      // Cache for 1 hour
      await redis.setex(cacheKey, 3600, JSON.stringify(report));

      logger.info('Compliance report generated', {
        period: `${startDate.toISOString()} - ${endDate.toISOString()}`,
        totalActions: totalActions.totalActions,
      });

      return report;
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      throw new AppError('Failed to generate compliance report', 500);
    }
  }

  /**
   * Get audit analytics
   */
  public static async getAuditAnalytics(
    startDate: Date,
    endDate: Date
  ): Promise<AuditAnalytics> {
    try {
      const cacheKey = `audit-analytics:${startDate.getTime()}-${endDate.getTime()}`;
      const cached = await redis.get(cacheKey);

      if (cached) {
        return JSON.parse(cached);
      }

      const [
        activityTrends,
        userBehaviorAnalysis,
        securityAnalysis,
        dataIntegrity,
      ] = await Promise.all([
        this.getActivityTrends(startDate, endDate),
        this.getUserBehaviorAnalysis(startDate, endDate),
        this.getSecurityAnalysis(startDate, endDate),
        this.getDataIntegrityMetrics(),
      ]);

      const analytics: AuditAnalytics = {
        timeRange: { start: startDate, end: endDate },
        activityTrends,
        userBehaviorAnalysis,
        securityAnalysis,
        dataIntegrity,
      };

      // Cache for 30 minutes
      await redis.setex(cacheKey, 1800, JSON.stringify(analytics));

      return analytics;
    } catch (error) {
      logger.error('Error generating audit analytics:', error);
      throw new AppError('Failed to generate audit analytics', 500);
    }
  }

  /**
   * Export audit logs to Excel
   */
  public static async exportAuditLogs(
    filters: AuditFilters = {},
    format: 'json' | 'excel' | 'csv' = 'excel'
  ): Promise<Buffer | any[]> {
    try {
      const where: any = {};

      // Apply same filters as getAuditLogs
      if (filters.userId) where.userId = filters.userId;
      if (filters.category) where.category = filters.category;
      if (filters.action) where.action = filters.action;
      if (filters.severity) where.severity = filters.severity;
      if (filters.startDate || filters.endDate) {
        where.createdAt = {};
        if (filters.startDate) where.createdAt.gte = filters.startDate;
        if (filters.endDate) where.createdAt.lte = filters.endDate;
      }

      const logs = await prisma.auditLog.findMany({
        where,
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              email: true,
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

      const exportData = logs.map(log => ({
        'Audit ID': log.id,
        'Action': log.action,
        'Category': log.category,
        'Severity': log.severity,
        'User': log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System',
        'User Role': log.user?.role || 'N/A',
        'Entity Type': log.entityType || 'N/A',
        'Entity ID': log.entityId || 'N/A',
        'Election': log.election?.title || 'N/A',
        'IP Address': log.ipAddress || 'N/A',
        'User Agent': log.userAgent || 'N/A',
        'Risk Level': (log.metadata as any)?.risk || 'N/A',
        'Flags': Array.isArray((log.metadata as any)?.flags) ? (log.metadata as any).flags.join(', ') : 'N/A',
        'Timestamp': log.createdAt.toISOString(),
        'Old Data': log.oldData ? JSON.stringify(log.oldData) : 'N/A',
        'New Data': log.newData ? JSON.stringify(log.newData) : 'N/A',
        'Metadata': log.metadata ? JSON.stringify(log.metadata) : 'N/A',
      }));

      if (format === 'json') {
        return exportData;
      }

      if (format === 'excel') {
        const worksheet = XLSX.utils.json_to_sheet(exportData);
        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Audit Logs');

        return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
      }

      // CSV format
      const worksheet = XLSX.utils.json_to_sheet(exportData);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Audit Logs');

      return XLSX.write(workbook, { type: 'buffer', bookType: 'csv' });
    } catch (error) {
      logger.error('Error exporting audit logs:', error);
      throw new AppError('Failed to export audit logs', 500);
    }
  }

  /**
   * Cleanup old audit logs (retention policy)
   */
  public static async cleanupOldLogs(): Promise<{ deleted: number }> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_DAYS);

      const result = await prisma.auditLog.deleteMany({
        where: {
          createdAt: {
            lt: cutoffDate,
          },
          // Keep critical logs longer
          NOT: {
            severity: 'CRITICAL',
          },
        },
      });

      logger.info('Old audit logs cleaned up', {
        deleted: result.count,
        cutoffDate: cutoffDate.toISOString(),
      });

      return { deleted: result.count };
    } catch (error) {
      logger.error('Error cleaning up old logs:', error);
      throw new AppError('Failed to cleanup old logs', 500);
    }
  }

  /**
   * Verify audit log integrity
   */
  public static async verifyAuditIntegrity(): Promise<{
    totalLogs: number;
    verifiedLogs: number;
    corruptedLogs: number;
    missingLogs: number;
    integrityScore: number;
  }> {
    try {
      const totalLogs = await prisma.auditLog.count();

      // Sample 10% of logs for integrity check
      const sampleSize = Math.max(100, Math.floor(totalLogs * 0.1));
      const sampleLogs = await prisma.auditLog.findMany({
        take: sampleSize,
        orderBy: { createdAt: 'desc' },
      });

      let verifiedLogs = 0;
      let corruptedLogs = 0;

      for (const log of sampleLogs) {
        try {
          // Verify log structure and data integrity
          if (this.verifyLogStructure(log)) {
            verifiedLogs++;
          } else {
            corruptedLogs++;
          }
        } catch (error) {
          corruptedLogs++;
        }
      }

      const integrityScore = (verifiedLogs / sampleLogs.length) * 100;

      return {
        totalLogs,
        verifiedLogs,
        corruptedLogs,
        missingLogs: 0, // Implement if sequential ID checking is needed
        integrityScore,
      };
    } catch (error) {
      logger.error('Error verifying audit integrity:', error);
      throw new AppError('Failed to verify audit integrity', 500);
    }
  }

  // Private helper methods

  private static assessRiskLevel(data: any): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const riskFactors = [];

    // Check for high-risk actions
    const highRiskActions = [
      'PASSWORD_CHANGED', 'ROLE_UPDATED', 'ELECTION_DELETED', 'USER_DELETED',
      'VOTE_MODIFIED', 'RESULT_MANIPULATED', 'ADMIN_ACCESS'
    ];

    if (highRiskActions.includes(data.action)) {
      riskFactors.push('high_risk_action');
    }

    // Check for admin actions
    if (data.category === 'ADMIN' || data.action.includes('ADMIN')) {
      riskFactors.push('admin_action');
    }

    // Check for election-related critical actions
    if (data.electionId && ['VOTE_CAST', 'VOTE_MODIFIED', 'ELECTION_ENDED'].includes(data.action)) {
      riskFactors.push('election_critical');
    }

    // Check for data modification
    if (data.oldData && data.newData) {
      riskFactors.push('data_modification');
    }

    // Determine risk level based on factors
    if (riskFactors.length >= 3) return 'CRITICAL';
    if (riskFactors.length >= 2) return 'HIGH';
    if (riskFactors.length >= 1) return 'MEDIUM';
    return 'LOW';
  }

  private static async detectSuspiciousPatterns(data: any): Promise<string[]> {
    const flags: string[] = [];

    // Check for rapid successive actions
    if (data.userId && data.action) {
      const recentActions = await prisma.auditLog.count({
        where: {
          userId: data.userId,
          action: data.action,
          createdAt: {
            gte: new Date(Date.now() - 60000), // Last minute
          },
        },
      });

      if (recentActions > 5) {
        flags.push('rapid_actions');
      }
    }

    // Check for unusual IP activity
    if (data.ipAddress) {
      const ipActions = await prisma.auditLog.count({
        where: {
          ipAddress: data.ipAddress,
          createdAt: {
            gte: new Date(Date.now() - 3600000), // Last hour
          },
        },
      });

      if (ipActions > 50) {
        flags.push('suspicious_ip');
      }
    }

    // Check for failed login patterns
    if (data.action === 'LOGIN_FAILED') {
      const recentFailures = await prisma.auditLog.count({
        where: {
          action: 'LOGIN_FAILED',
          ipAddress: data.ipAddress,
          createdAt: {
            gte: new Date(Date.now() - 900000), // Last 15 minutes
          },
        },
      });

      if (recentFailures > 3) {
        flags.push('brute_force_attempt');
      }
    }

    return flags;
  }

  private static async logToExternalAuditSystem(auditEntry: AuditLog): Promise<void> {
    try {
      // In a real implementation, this would send to external audit systems
      // like Splunk, ElasticSearch, or compliance logging services
      logger.info('External audit log', {
        auditId: auditEntry.id,
        action: auditEntry.action,
        severity: auditEntry.severity,
        timestamp: auditEntry.createdAt,
      });
    } catch (error) {
      logger.error('Failed to log to external audit system:', error);
    }
  }

  private static async triggerSecurityAlert(auditEntry: AuditLog): Promise<void> {
    try {
      // In a real implementation, this would trigger alerts to security team
      logger.warn('SECURITY ALERT', {
        auditId: auditEntry.id,
        action: auditEntry.action,
        severity: auditEntry.severity,
        userId: auditEntry.userId,
        ipAddress: auditEntry.ipAddress,
      });

      // You could integrate with services like PagerDuty, Slack, or email alerts
    } catch (error) {
      logger.error('Failed to trigger security alert:', error);
    }
  }

  private static enrichAuditLog(log: any): AuditLogEntry {
    return {
      id: log.id,
      action: log.action,
      category: log.category,
      severity: log.severity,
      userId: log.userId,
      userName: log.user ? `${log.user.firstName} ${log.user.lastName}` : undefined,
      userRole: log.user?.role,
      entityType: log.entityType,
      entityId: log.entityId,
      electionId: log.electionId,
      electionTitle: log.election?.title,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      sessionId: log.metadata?.sessionId,
      oldData: log.oldData,
      newData: log.newData,
      metadata: log.metadata,
      timestamp: log.createdAt,
      location: log.metadata?.location,
      deviceInfo: log.metadata?.deviceInfo,
      risk: log.metadata?.risk,
      flags: log.metadata?.flags || [],
    };
  }

  private static generateSecurityEventDescription(event: any): string {
    const action = event.action;
    const user = event.user ? `${event.user.firstName} ${event.user.lastName}` : 'Unknown user';

    switch (action) {
      case 'LOGIN_FAILED':
        return `Failed login attempt by ${user}`;
      case 'SUSPICIOUS_ACTIVITY':
        return `Suspicious activity detected for ${user}`;
      case 'ROLE_ESCALATION':
        return `Unauthorized role escalation attempt by ${user}`;
      case 'VOTE_MANIPULATION':
        return `Potential vote manipulation detected for ${user}`;
      default:
        return `Security event: ${action} by ${user}`;
    }
  }

  private static verifyLogStructure(log: any): boolean {
    // Implement log structure verification logic
    return !!(log.id && log.action && log.category && log.severity && log.createdAt);
  }

  // Analytics helper methods
  private static async getTotalActionsInPeriod(startDate: Date, endDate: Date) {
    const [total, userActions, adminActions, systemActions, securityEvents, dataChanges, accessAttempts] = await Promise.all([
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate } } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, userId: { not: null } } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, category: 'SYSTEM' as any } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, userId: null } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, severity: { in: ['HIGH', 'CRITICAL'] } } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, oldData: { not: undefined as any } } }),
      prisma.auditLog.count({ where: { createdAt: { gte: startDate, lte: endDate }, action: { contains: 'ACCESS' } } }),
    ]);

    return {
      totalActions: total,
      userActions,
      adminActions,
      systemActions,
      securityEvents,
      dataChanges,
      accessAttempts,
    };
  }

  private static async getCategorizedActivity(startDate: Date, endDate: Date) {
    const categories = await prisma.auditLog.groupBy({
      by: ['category'],
      where: { createdAt: { gte: startDate, lte: endDate } },
      _count: true,
    });

    const total = categories.reduce((sum, cat) => sum + cat._count, 0);

    return categories.map(cat => ({
      category: cat.category,
      count: cat._count,
      percentage: total > 0 ? (cat._count / total) * 100 : 0,
    }));
  }

  private static async getUserActivitySummary(startDate: Date, endDate: Date) {
    const userActivity = await prisma.auditLog.groupBy({
      by: ['userId'],
      where: {
        createdAt: { gte: startDate, lte: endDate },
        userId: { not: null },
      },
      _count: true,
      _max: { createdAt: true },
    });

    const userDetails = await Promise.all(
      userActivity.map(async (activity) => {
        const user = await prisma.user.findUnique({
          where: { id: activity.userId! },
          select: { firstName: true, lastName: true, role: true },
        });

        return {
          userId: activity.userId!,
          userName: user ? `${user.firstName} ${user.lastName}` : 'Unknown',
          role: (user?.role || 'VOTER') as UserRole,
          actionCount: activity._count,
          lastActivity: activity._max.createdAt!,
          riskScore: await this.calculateUserRiskScore(activity.userId!, startDate, endDate),
        };
      })
    );

    return userDetails.sort((a, b) => b.actionCount - a.actionCount);
  }

  private static async getElectionActivitySummary(startDate: Date, endDate: Date) {
    const electionActivity = await prisma.auditLog.groupBy({
      by: ['electionId'],
      where: {
        createdAt: { gte: startDate, lte: endDate },
        electionId: { not: null },
      },
      _count: true,
      _max: { createdAt: true },
    });

    return Promise.all(
      electionActivity.map(async (activity) => {
        const election = await prisma.election.findUnique({
          where: { id: activity.electionId! },
          select: { title: true },
        });

        const [voterActivity, adminActivity] = await Promise.all([
          prisma.auditLog.count({
            where: {
              electionId: activity.electionId,
              createdAt: { gte: startDate, lte: endDate },
              category: { in: ['VOTING' as any, 'USER' as any] },
            },
          }),
          prisma.auditLog.count({
            where: {
              electionId: activity.electionId,
              createdAt: { gte: startDate, lte: endDate },
              category: 'SYSTEM' as any,
            },
          }),
        ]);

        return {
          electionId: activity.electionId!,
          electionTitle: election?.title || 'Unknown Election',
          actionCount: activity._count,
          voterActivity,
          adminActivity,
          lastActivity: activity._max.createdAt!,
        };
      })
    );
  }

  private static async getSecurityMetrics(startDate: Date, endDate: Date) {
    const [highRiskActions, suspiciousPatterns, failedAttempts, unusualActivity] = await Promise.all([
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          metadata: { path: ['risk'], equals: 'HIGH' as any },
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          metadata: { path: ['flags'], not: { equals: [] as any } },
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          action: { contains: 'FAILED' },
        },
      }),
      prisma.auditLog.count({
        where: {
          createdAt: { gte: startDate, lte: endDate },
          severity: 'HIGH',
        },
      }),
    ]);

    return {
      riskAssessment: {
        highRiskActions,
        suspiciousPatterns,
        failedAttempts,
        unusualActivity,
      },
      systemMetrics: {
        averageResponseTime: 150, // TODO: Calculate from actual metrics
        errorRate: 0.5, // TODO: Calculate from actual metrics
        uptimePercentage: 99.9, // TODO: Calculate from actual metrics
        securityIncidents: highRiskActions + suspiciousPatterns,
      },
    };
  }

  private static async getActivityTrends(startDate: Date, endDate: Date) {
    // Generate daily activity trends
    const trends = [];
    const currentDate = new Date(startDate);

    while (currentDate <= endDate) {
      const dayStart = new Date(currentDate);
      const dayEnd = new Date(currentDate);
      dayEnd.setDate(dayEnd.getDate() + 1);

      const [total, userActions, adminActions, systemActions] = await Promise.all([
        prisma.auditLog.count({ where: { createdAt: { gte: dayStart, lt: dayEnd } } }),
        prisma.auditLog.count({ where: { createdAt: { gte: dayStart, lt: dayEnd }, userId: { not: null } } }),
        prisma.auditLog.count({ where: { createdAt: { gte: dayStart, lt: dayEnd }, category: 'SYSTEM' as any } }),
        prisma.auditLog.count({ where: { createdAt: { gte: dayStart, lt: dayEnd }, userId: null } }),
      ]);

      trends.push({
        date: currentDate.toISOString().split('T')[0],
        count: total,
        userActions,
        adminActions,
        systemActions,
      });

      currentDate.setDate(currentDate.getDate() + 1);
    }

    return trends;
  }

  private static async getUserBehaviorAnalysis(startDate: Date, endDate: Date) {
    // Most active users
    const mostActiveUsers = await prisma.auditLog.groupBy({
      by: ['userId'],
      where: {
        createdAt: { gte: startDate, lte: endDate },
        userId: { not: null },
      },
      _count: true,
      orderBy: { _count: { userId: 'desc' } },
      take: 10,
    });

    const mostActiveUsersDetails = await Promise.all(
      mostActiveUsers.map(async (user) => {
        const userDetails = await prisma.user.findUnique({
          where: { id: user.userId! },
          select: { firstName: true, lastName: true },
        });

        return {
          userId: user.userId!,
          userName: userDetails ? `${userDetails.firstName} ${userDetails.lastName}` : 'Unknown',
          actionCount: user._count,
        };
      })
    );

    // Access patterns by hour
    const accessPatterns = Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0 }));

    const hourlyData = await prisma.auditLog.findMany({
      where: { createdAt: { gte: startDate, lte: endDate } },
      select: { createdAt: true },
    });

    hourlyData.forEach(log => {
      const hour = log.createdAt.getHours();
      accessPatterns[hour].count++;
    });

    return {
      mostActiveUsers: mostActiveUsersDetails,
      suspiciousActivity: [], // TODO: Implement suspicious activity detection
      accessPatterns,
    };
  }

  private static async getSecurityAnalysis(startDate: Date, endDate: Date) {
    const failedLogins = await prisma.auditLog.count({
      where: {
        createdAt: { gte: startDate, lte: endDate },
        action: 'LOGIN_FAILED',
      },
    });

    const suspiciousIPs = await prisma.auditLog.groupBy({
      by: ['ipAddress'],
      where: {
        createdAt: { gte: startDate, lte: endDate },
        action: 'LOGIN_FAILED',
        ipAddress: { not: null },
      },
      _count: true,
      _max: { createdAt: true },
      having: { ipAddress: { _count: { gte: 3 } } },
    });

    return {
      failedLogins,
      suspiciousIPs: suspiciousIPs.map(ip => ({
        ip: ip.ipAddress!,
        attempts: ip._count,
        lastSeen: ip._max.createdAt!,
      })),
      anomalies: [], // TODO: Implement anomaly detection
    };
  }

  private static async getDataIntegrityMetrics() {
    const totalLogs = await prisma.auditLog.count();

    return {
      totalChecks: totalLogs,
      passedChecks: totalLogs, // TODO: Implement actual integrity checks
      failedChecks: 0,
      lastCheck: new Date(),
    };
  }

  private static async calculateUserRiskScore(userId: string, startDate: Date, endDate: Date): Promise<number> {
    const [
      totalActions,
      highRiskActions,
      suspiciousFlags,
      failedAttempts,
    ] = await Promise.all([
      prisma.auditLog.count({
        where: { userId, createdAt: { gte: startDate, lte: endDate } },
      }),
      prisma.auditLog.count({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate },
          metadata: { path: ['risk'], equals: 'HIGH' as any },
        },
      }),
      prisma.auditLog.count({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate },
          metadata: { path: ['flags'], not: { equals: [] as any } },
        },
      }),
      prisma.auditLog.count({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate },
          action: { contains: 'FAILED' },
        },
      }),
    ]);

    // Calculate risk score (0-100)
    let riskScore = 0;

    if (totalActions > 0) {
      riskScore += (highRiskActions / totalActions) * 40;
      riskScore += (suspiciousFlags / totalActions) * 30;
      riskScore += (failedAttempts / totalActions) * 30;
    }

    return Math.min(100, Math.round(riskScore));
  }

  /**
   * Get system alerts for dashboard
   */
  public static async getSystemAlerts(): Promise<any[]> {
    try {
      const alerts = [];
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

      // Get critical security events from the last hour
      const securityEvents = await this.getSecurityEvents(
        {
          severity: ['HIGH', 'CRITICAL'],
          dateRange: { from: oneHourAgo, to: now },
        },
        1,
        20
      );

      // Convert security events to system alerts
      for (const event of securityEvents.events) {
        alerts.push({
          id: event.id,
          type: event.severity === 'CRITICAL' ? 'error' : 'warning',
          severity: event.severity.toLowerCase(),
          title: this.getAlertTitle(event.type),
          message: event.description || event.type,
          source: 'security_system',
          timestamp: event.timestamp,
          acknowledged: event.resolved || false,
          actionRequired: !event.resolved,
          metadata: event.metadata || {},
        });
      }

      // Check for system performance issues
      const recentErrors = await prisma.auditLog.count({
        where: {
          category: 'SYSTEM',
          severity: { in: ['HIGH', 'CRITICAL'] },
          createdAt: { gte: oneHourAgo },
        },
      });

      if (recentErrors > 10) {
        alerts.push({
          id: 'system_errors',
          type: 'warning',
          severity: 'medium',
          title: 'High Error Rate',
          message: `${recentErrors} system errors detected in the last hour`,
          source: 'system_monitoring',
          timestamp: now,
          acknowledged: false,
          actionRequired: true,
          metadata: { errorCount: recentErrors },
        });
      }

      // Check for suspicious login attempts
      const suspiciousLogins = await this.detectSuspiciousActivity('SUSPICIOUS_LOGIN', oneHourAgo);
      if (suspiciousLogins.length > 0) {
        alerts.push({
          id: 'suspicious_logins',
          type: 'error',
          severity: 'high',
          title: 'Suspicious Login Activity',
          message: `${suspiciousLogins.length} suspicious login attempts detected`,
          source: 'security_monitoring',
          timestamp: now,
          acknowledged: false,
          actionRequired: true,
          metadata: { attempts: suspiciousLogins.length },
        });
      }

      // Sort by severity and timestamp
      return alerts.sort((a, b) => {
        const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const aSeverity = severityOrder[a.severity] || 0;
        const bSeverity = severityOrder[b.severity] || 0;

        if (aSeverity !== bSeverity) {
          return bSeverity - aSeverity;
        }

        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      });

    } catch (error) {
      logger.error('Error getting system alerts:', error);
      return [];
    }
  }

  /**
   * Get alert title from action
   */
  private static getAlertTitle(action: string): string {
    const titleMap: Record<string, string> = {
      'LOGIN_FAILED': 'Failed Login Attempts',
      'SUSPICIOUS_ACTIVITY': 'Suspicious Activity Detected',
      'SYSTEM_ERROR': 'System Error',
      'SECURITY_VIOLATION': 'Security Violation',
      'DATA_BREACH_ATTEMPT': 'Data Breach Attempt',
      'UNAUTHORIZED_ACCESS': 'Unauthorized Access',
      'ELECTION_MANIPULATION': 'Election Manipulation Attempt',
      'VOTE_TAMPERING': 'Vote Tampering Detected',
    };

    return titleMap[action] || action.replace('_', ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Detect specific types of suspicious activity
   */
  private static async detectSuspiciousActivity(type: string, since: Date): Promise<any[]> {
    try {
      const logs = await prisma.auditLog.findMany({
        where: {
          action: { contains: type },
          createdAt: { gte: since },
          severity: { in: ['HIGH', 'CRITICAL'] },
        },
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        take: 50,
      });

      return logs.map(log => ({
        id: log.id,
        userId: log.userId,
        user: log.user,
        action: log.action,
        ipAddress: log.ipAddress,
        timestamp: log.createdAt,
        metadata: log.metadata,
      }));
    } catch (error) {
      logger.error('Error detecting suspicious activity:', error);
      return [];
    }
  }
}

// Export singleton instance
export const auditService = AuditService;
export default AuditService;