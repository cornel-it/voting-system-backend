import { PrismaClient, Notification, NotificationType, NotificationPriority } from '@prisma/client';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { logger } from '../utils/logger';
import { AppError } from '../utils/errors';
// @ts-ignore
import cron from 'node-cron';

export interface CreateNotificationData {
  userId: string;
  title: string;
  message: string;
  type: NotificationType;
  priority: NotificationPriority;
  data?: any;
  actionUrl?: string;
  channels: ('email' | 'sms' | 'push')[];
  expiresAt?: Date;
}

export interface BulkNotificationData {
  userIds: string[];
  title: string;
  message: string;
  type: NotificationType;
  priority: NotificationPriority;
  data?: any;
  actionUrl?: string;
  channels: ('email' | 'sms' | 'push')[];
  expiresAt?: Date;
}

export interface NotificationStats {
  total: number;
  unread: number;
  byType: Record<NotificationType, number>;
  byPriority: Record<NotificationPriority, number>;
  byChannel: {
    email: { sent: number; failed: number };
    sms: { sent: number; failed: number };
    push: { sent: number; failed: number };
  };
}

export class NotificationService {
  private static readonly BATCH_SIZE = 100;
  private static readonly CACHE_TTL = 300; // 5 minutes
  private static scheduledJobs = new Map<string, any>();

  // ===============================
  // CANDIDATE NOTIFICATION METHODS
  // ===============================

  /**
   * Notify candidate when their application is approved
   */
  static async notifyCandidateApproved(candidateId: string, electionTitle: string): Promise<void> {
    try {
      const candidate = await prisma.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true }
      }) as any;

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Get user separately - use studentId to find the user
      const user = await prisma.user.findUnique({
        where: { id: candidate.studentId }
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Create in-app notification
      await this.createNotification({
        userId: candidate.id,
        title: 'Application Approved!',
        message: `Congratulations! Your application for "${electionTitle}" has been approved. You can now start your campaign.`,
        type: 'SYSTEM_UPDATE',
        priority: 'HIGH',
        channels: ['email', 'push'],
        actionUrl: `/elections/${candidate.electionId}/candidate-dashboard`,
        data: {
          electionId: candidate.electionId,
          candidateId: candidateId,
          position: candidate.position
        }
      });

      // Send email notification
      await emailService.sendCandidateApprovalEmail(
        {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        },
        {
          title: candidate.election?.title || electionTitle,
          id: candidate.electionId
        },
        candidate.position?.name || 'Candidate'
      );

      logger.info(`Candidate approval notification sent to ${user.email}`);
    } catch (error) {
      logger.error('Error sending candidate approval notification:', error);
      throw error;
    }
  }

  /**
   * Notify candidate when their application is rejected
   */
  static async notifyCandidateRejected(candidateId: string, electionTitle: string, reason?: string): Promise<void> {
    try {
      const candidate = await prisma.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true }
      }) as any;

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Get user separately - use studentId to find the user
      const user = await prisma.user.findUnique({
        where: { id: candidate.studentId }
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const reasonText = reason ? ` Reason: ${reason}` : '';

      // Create in-app notification
      await this.createNotification({
        userId: candidate.id,
        title: 'Application Status Update',
        message: `Your application for "${electionTitle}" requires revision.${reasonText} Please review and resubmit.`,
        type: 'SYSTEM_UPDATE',
        priority: 'HIGH',
        channels: ['email', 'push'],
        actionUrl: `/elections/${candidate.electionId}/apply`,
        data: {
          electionId: candidate.electionId,
          candidateId: candidateId,
          rejectionReason: reason
        }
      });

      // Send email notification
      await emailService.sendCandidateRejectionEmail(
        {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        },
        {
          title: candidate.election?.title || electionTitle,
          id: candidate.electionId
        },
        reason || 'Please review your application and make necessary corrections.'
      );

      logger.info(`Candidate rejection notification sent to ${user.email}`);
    } catch (error) {
      logger.error('Error sending candidate rejection notification:', error);
      throw error;
    }
  }

  /**
   * Notify candidates about campaign milestones
   */
  static async notifyCandidateCampaignMilestone(candidateId: string, milestone: string, data?: any): Promise<void> {
    try {
      const candidate = await prisma.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true }
      }) as any;

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Get user separately - use studentId to find the user
      const user = await prisma.user.findUnique({
        where: { id: candidate.studentId }
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      await this.createNotification({
        userId: candidate.id,
        title: `Campaign Update: ${milestone}`,
        message: `Important update regarding your campaign for "${candidate.election?.title}".`,
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email', 'push'],
        actionUrl: `/elections/${candidate.electionId}/candidate-dashboard`,
        data: {
          milestone,
          ...data
        }
      });

      logger.info(`Campaign milestone notification sent to candidate ${user.email}`);
    } catch (error) {
      logger.error('Error sending campaign milestone notification:', error);
      throw error;
    }
  }

  // ===============================
  // ADMIN/MODERATOR NOTIFICATION METHODS
  // ===============================

  /**
   * Notify admins of system security events
   */
  static async notifyAdminsSecurityEvent(eventType: string, details: any, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM'): Promise<void> {
    try {
      const admins = await prisma.user.findMany({
        where: {
          role: { in: ['ADMIN', 'SUPER_ADMIN', 'MODERATOR'] },
          isActive: true
        }
      });

      const priority = severity === 'CRITICAL' ? 'HIGH' : severity === 'HIGH' ? 'HIGH' : 'MEDIUM';
      const channels: ('email' | 'sms' | 'push')[] = severity === 'CRITICAL' ? ['email', 'sms', 'push'] : ['email', 'push'];

      // Create in-app notifications
      await this.createBulkNotifications({
        userIds: admins.map(a => a.id),
        title: `Security Alert: ${eventType}`,
        message: `Security event detected. Severity: ${severity}. Immediate attention may be required.`,
        type: 'SECURITY_ALERT',
        priority: priority as NotificationPriority,
        channels,
        actionUrl: '/admin/security/events',
        data: {
          eventType,
          severity,
          details,
          timestamp: new Date().toISOString()
        }
      });

      // Send email notifications
      await emailService.sendSecurityAlertEmail(
        admins.map(a => ({
          email: a.email,
          firstName: a.firstName
        })),
        eventType,
        details,
        severity
      );

      logger.warn(`Security event notification sent to ${admins.length} admins: ${eventType}`);
    } catch (error) {
      logger.error('Error sending security event notification:', error);
      throw error;
    }
  }

  /**
   * Notify admins when new elections are created
   */
  static async notifyAdminsElectionCreated(electionId: string, createdBy: string): Promise<void> {
    try {
      const election = await prisma.election.findUnique({
        where: { id: electionId },
        include: { createdBy: true }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      const admins = await prisma.user.findMany({
        where: {
          role: { in: ['ADMIN', 'SUPER_ADMIN'] },
          isActive: true,
          id: { not: createdBy } // Don't notify the creator
        }
      });

      await this.createBulkNotifications({
        userIds: admins.map(a => a.id),
        title: '📊 New Election Created',
        message: `A new election "${election.title}" has been created and requires review.`,
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email', 'push'],
        actionUrl: `/admin/elections/${electionId}`,
        data: {
          electionId,
          electionTitle: election.title,
          createdBy: election.createdBy?.email
        }
      });

      logger.info(`Election creation notification sent to ${admins.length} admins`);
    } catch (error) {
      logger.error('Error sending election creation notification:', error);
      throw error;
    }
  }

  /**
   * Notify moderators of candidate applications requiring review
   */
  static async notifyModeratorsNewCandidateApplication(candidateId: string): Promise<void> {
    try {
      const candidate = await prisma.candidate.findUnique({
        where: { id: candidateId },
        include: { election: true, position: true }
      }) as any;

      if (!candidate) {
        throw new AppError('Candidate not found', 404);
      }

      // Get user separately
      const user = await prisma.user.findUnique({
        where: { id: candidate.id }
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      const moderators = await prisma.user.findMany({
        where: {
          role: { in: ['MODERATOR', 'ADMIN', 'SUPER_ADMIN'] },
          isActive: true
        }
      });

      // Create in-app notifications
      await this.createBulkNotifications({
        userIds: moderators.map(m => m.id),
        title: 'New Candidate Application',
        message: `${user.firstName} ${user.lastName} has applied as a candidate for "${candidate.election?.title}".`,
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email', 'push'],
        actionUrl: `/admin/candidates/${candidateId}/review`,
        data: {
          candidateId,
          candidateName: `${user.firstName} ${user.lastName}`,
          electionId: candidate.electionId,
          electionTitle: candidate.election?.title,
          position: candidate.position?.name
        }
      });

      // Send email notifications to moderators
      await emailService.sendCandidateApplicationNotification(
        moderators.map(m => ({
          email: m.email,
          firstName: m.firstName
        })),
        {
          firstName: user.firstName,
          lastName: user.lastName,
          studentId: user.studentId
        },
        {
          title: candidate.election?.title,
          id: candidate.electionId
        },
        candidate.position?.name || 'Candidate',
        candidateId
      );

      logger.info(`Candidate application notification sent to ${moderators.length} moderators`);
    } catch (error) {
      logger.error('Error sending candidate application notification:', error);
      throw error;
    }
  }

  /**
   * Notify admins of system maintenance or updates
   */
  static async notifyAdminsSystemMaintenance(title: string, message: string, scheduledTime?: Date): Promise<void> {
    try {
      const admins = await prisma.user.findMany({
        where: {
          role: { in: ['ADMIN', 'SUPER_ADMIN'] },
          isActive: true
        }
      });

      await this.createBulkNotifications({
        userIds: admins.map(a => a.id),
        title: `🔧 ${title}`,
        message,
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email', 'push'],
        actionUrl: '/admin/system/maintenance',
        data: {
          maintenanceTitle: title,
          scheduledTime: scheduledTime?.toISOString(),
          notifiedAt: new Date().toISOString()
        }
      });

      logger.info(`System maintenance notification sent to ${admins.length} admins`);
    } catch (error) {
      logger.error('Error sending system maintenance notification:', error);
      throw error;
    }
  }

  // ===============================
  // VOTER ENHANCED NOTIFICATION METHODS
  // ===============================

  /**
   * Notify voters about upcoming election deadlines
   */
  static async notifyVotersElectionDeadline(electionId: string, deadlineType: 'registration' | 'voting', hoursRemaining: number): Promise<void> {
    try {
      const election = await prisma.election.findUnique({
        where: { id: electionId }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      // Get eligible voters who haven't voted yet (for voting deadline) or all eligible voters (for registration)
      const whereClause = deadlineType === 'voting'
        ? {
            isActive: true,
            isVerified: true,
            votes: {
              none: {
                electionId: electionId
              }
            }
          }
        : {
            isActive: true,
            isVerified: true
          };

      const voters = await prisma.user.findMany({
        where: whereClause
      });

      const urgencyLevel = hoursRemaining <= 24 ? 'HIGH' : hoursRemaining <= 72 ? 'MEDIUM' : 'LOW';
      const timeText = hoursRemaining < 24
        ? `${hoursRemaining} hours`
        : `${Math.floor(hoursRemaining / 24)} days`;

      await this.createBulkNotifications({
        userIds: voters.map(v => v.id),
        title: `⏰ ${deadlineType === 'voting' ? 'Voting' : 'Registration'} Deadline Approaching`,
        message: `Only ${timeText} left to ${deadlineType === 'voting' ? 'cast your vote' : 'register'} for "${election.title}". Don't miss your chance to participate!`,
        type: 'SYSTEM_UPDATE',
        priority: urgencyLevel as NotificationPriority,
        channels: urgencyLevel === 'HIGH' ? ['email', 'sms', 'push'] : ['email', 'push'],
        actionUrl: deadlineType === 'voting' ? `/elections/${electionId}/vote` : `/elections/${electionId}`,
        data: {
          electionId,
          deadlineType,
          hoursRemaining,
          electionTitle: election.title
        }
      });

      logger.info(`Election deadline notification sent to ${voters.length} voters`);
    } catch (error) {
      logger.error('Error sending election deadline notification:', error);
      throw error;
    }
  }

  /**
   * Notify voters when they're eligible for a new election
   */
  static async notifyVotersElectionEligibility(electionId: string): Promise<void> {
    try {
      const election = await prisma.election.findUnique({
        where: { id: electionId }
      });

      if (!election) {
        throw new AppError('Election not found', 404);
      }

      // Get all active, verified voters
      const voters = await prisma.user.findMany({
        where: {
          role: 'VOTER',
          isActive: true,
          isVerified: true
        }
      });

      await this.createBulkNotifications({
        userIds: voters.map(v => v.id),
        title: '🗳️ New Election Available',
        message: `You're eligible to participate in "${election.title}". Learn about the candidates and make your voice heard!`,
        type: 'SYSTEM_UPDATE',
        priority: 'MEDIUM',
        channels: ['email', 'push'],
        actionUrl: `/elections/${electionId}`,
        data: {
          electionId,
          electionTitle: election.title,
          startDate: election.startDate?.toISOString(),
          endDate: election.endDate?.toISOString()
        }
      });

      logger.info(`Election eligibility notification sent to ${voters.length} voters`);
    } catch (error) {
      logger.error('Error sending election eligibility notification:', error);
      throw error;
    }
  }

  // ===============================
  // DIGEST AND SUMMARY METHODS
  // ===============================

  /**
   * Send daily digest to admins with system summary
   */
  static async sendDailyDigest(): Promise<void> {
    try {
      const today = new Date();
      const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

      // Get stats for the last 24 hours
      const [
        newUsers,
        newCandidates,
        activeElections,
        totalVotes,
        securityEvents,
        systemNotifications
      ] = await Promise.all([
        prisma.user.count({
          where: {
            createdAt: { gte: yesterday }
          }
        }),
        prisma.candidate.count({
          where: {
            createdAt: { gte: yesterday }
          }
        }),
        prisma.election.count({
          where: {
            status: 'ACTIVE'
          }
        }),
        prisma.vote.count({
          where: {
            castAt: { gte: yesterday }
          }
        }),
        prisma.securityEvent.count({
          where: {
            createdAt: { gte: yesterday }
          }
        }),
        prisma.notification.count({
          where: {
            createdAt: { gte: yesterday },
            type: 'SYSTEM_UPDATE'
          }
        })
      ]);

      const admins = await prisma.user.findMany({
        where: {
          role: { in: ['ADMIN', 'SUPER_ADMIN'] },
          isActive: true
        }
      });

      const stats = {
        newUsers,
        newCandidates,
        activeElections,
        totalVotes,
        securityEvents,
        systemNotifications
      };

      const digestData = {
        date: today.toDateString(),
        stats
      };

      // Create in-app notifications
      await this.createBulkNotifications({
        userIds: admins.map(a => a.id),
        title: `Daily System Digest - ${today.toDateString()}`,
        message: `Daily system summary: ${newUsers} new users, ${newCandidates} new candidates, ${totalVotes} votes cast, ${securityEvents} security events.`,
        type: 'SYSTEM_UPDATE',
        priority: 'LOW',
        channels: ['email'],
        actionUrl: '/admin/dashboard',
        data: digestData
      });

      // Send email digest
      await emailService.sendDailyDigestEmail(
        admins.map(a => ({
          email: a.email,
          firstName: a.firstName
        })),
        stats,
        today.toDateString()
      );

      logger.info(`Daily digest sent to ${admins.length} admins`);
    } catch (error) {
      logger.error('Error sending daily digest:', error);
      throw error;
    }
  }

  /**
   * Get notification summary for dashboard
   */
  static async getNotificationSummary(userId: string): Promise<{
    unreadCount: number;
    priorityCounts: Record<NotificationPriority, number>;
    typeCounts: Record<NotificationType, number>;
    recentNotifications: any[];
  }> {
    try {
      const [unreadCount, notifications] = await Promise.all([
        prisma.notification.count({
          where: {
            userId,
            read: false,
            expiresAt: { gt: new Date() }
          }
        }),
        prisma.notification.findMany({
          where: {
            userId,
            expiresAt: { gt: new Date() }
          },
          orderBy: { createdAt: 'desc' },
          take: 10
        })
      ]);

      const priorityCounts = notifications.reduce((acc, notif) => {
        acc[notif.priority] = (acc[notif.priority] || 0) + 1;
        return acc;
      }, {} as Record<NotificationPriority, number>);

      const typeCounts = notifications.reduce((acc, notif) => {
        acc[notif.type] = (acc[notif.type] || 0) + 1;
        return acc;
      }, {} as Record<NotificationType, number>);

      return {
        unreadCount,
        priorityCounts,
        typeCounts,
        recentNotifications: notifications.slice(0, 5)
      };
    } catch (error) {
      logger.error('Error getting notification summary:', error);
      throw error;
    }
  }

  /**
   * Mark notification as read by specific user
   */
  static async markNotificationAsRead(notificationId: string, userId: string): Promise<void> {
    try {
      await prisma.notification.updateMany({
        where: {
          id: notificationId,
          userId: userId
        },
        data: {
          read: true,
          readAt: new Date()
        }
      });

      await this.clearUserNotificationCache(userId);
      logger.info(`Notification ${notificationId} marked as read for user ${userId}`);
    } catch (error) {
      logger.error('Error marking notification as read:', error);
      throw error;
    }
  }

  /**
   * Mark multiple notifications as read
   */
  static async markMultipleAsRead(notificationIds: string[], userId: string): Promise<void> {
    try {
      await prisma.notification.updateMany({
        where: {
          id: { in: notificationIds },
          userId: userId
        },
        data: {
          read: true,
          readAt: new Date()
        }
      });

      await this.clearUserNotificationCache(userId);
      logger.info(`${notificationIds.length} notifications marked as read for user ${userId}`);
    } catch (error) {
      logger.error('Error marking multiple notifications as read:', error);
      throw error;
    }
  }

  /**
   * Get user notification preferences
   */
  static async getUserNotificationPreferences(userId: string): Promise<any> {
    try {
      const preferences = await prisma.userPreferences.findFirst({
        where: { userId },
        select: {
          emailNotifications: true,
          smsNotifications: true,
          pushNotifications: true
        }
      });

      return preferences || {
        emailNotifications: true,
        smsNotifications: false,
        pushNotifications: true
      };
    } catch (error) {
      logger.error('Error getting notification preferences:', error);
      throw error;
    }
  }

  /**
   * Update user notification preferences
   */
  static async updateNotificationPreferences(userId: string, preferences: any): Promise<any> {
    try {
      const updatedPreferences = await prisma.userPreferences.upsert({
        where: { userId },
        update: preferences,
        create: {
          userId,
          ...preferences
        }
      });

      logger.info(`Notification preferences updated for user ${userId}`);
      return updatedPreferences;
    } catch (error) {
      logger.error('Error updating notification preferences:', error);
      throw error;
    }
  }

  /**
   * Get comprehensive notification statistics
   */
  static async getNotificationStatistics(): Promise<any> {
    try {
      const [
        totalNotifications,
        unreadNotifications,
        typeBreakdown,
        priorityBreakdown,
        channelStats,
        recentActivity
      ] = await Promise.all([
        prisma.notification.count(),
        prisma.notification.count({ where: { read: false } }),
        prisma.notification.groupBy({
          by: ['type'],
          _count: { type: true }
        }),
        prisma.notification.groupBy({
          by: ['priority'],
          _count: { priority: true }
        }),
        prisma.notification.groupBy({
          by: ['channels'],
          _count: { channels: true }
        }),
        prisma.notification.findMany({
          take: 10,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            type: true,
            priority: true,
            createdAt: true,
            read: true
          }
        })
      ]);

      return {
        overview: {
          total: totalNotifications,
          unread: unreadNotifications,
          readRate: totalNotifications > 0 ? ((totalNotifications - unreadNotifications) / totalNotifications * 100).toFixed(2) : 0
        },
        breakdown: {
          byType: typeBreakdown.reduce((acc, item) => {
            acc[item.type] = item._count.type;
            return acc;
          }, {} as Record<string, number>),
          byPriority: priorityBreakdown.reduce((acc, item) => {
            acc[item.priority] = item._count.priority;
            return acc;
          }, {} as Record<string, number>)
        },
        channels: channelStats,
        recentActivity
      };
    } catch (error) {
      logger.error('Error getting notification statistics:', error);
      throw error;
    }
  }

  /**
   * Initialize notification service
   */
  public static initialize(): void {
    // Schedule cleanup job for expired notifications
    const cleanupJob = cron.schedule('0 0 * * *', async () => {
      await this.cleanupExpiredNotifications();
    }, {
      scheduled: false,
    });

    cleanupJob.start();
    this.scheduledJobs.set('cleanup', cleanupJob);

    // Schedule daily digest job
    const digestJob = cron.schedule('0 8 * * *', async () => {
      await this.sendDailyDigest();
    }, {
      scheduled: false,
    });

    digestJob.start();
    this.scheduledJobs.set('digest', digestJob);

    logger.info('Notification service initialized with scheduled jobs');
  }

  /**
   * Create a new notification
   */
  public static async createNotification(
    notificationData: CreateNotificationData
  ): Promise<Notification> {
    return await prisma.$transaction(async (tx) => {
      // Verify user exists
      const user = await tx.user.findUnique({
        where: { id: notificationData.userId },
        select: {
          id: true,
          email: true,
          phone: true,
          firstName: true,
          lastName: true,
        },
      });

      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Create notification record
      const notification = await tx.notification.create({
        data: {
          userId: notificationData.userId,
          title: notificationData.title,
          message: notificationData.message,
          type: notificationData.type,
          priority: notificationData.priority,
          data: notificationData.data || {},
          actionUrl: notificationData.actionUrl,
          channels: notificationData.channels,
          expiresAt: notificationData.expiresAt,
        },
      });

      // Send notifications through specified channels
      await this.deliverNotification(notification, user);

      // Cache for real-time updates
      await this.cacheNotification(notification);

      logger.info('Notification created', {
        notificationId: notification.id,
        userId: notificationData.userId,
        type: notificationData.type,
        channels: notificationData.channels,
      });

      return notification;
    });
  }

  /**
   * Create bulk notifications
   */
  public static async createBulkNotifications(
    notificationData: BulkNotificationData
  ): Promise<{ created: number; failed: number }> {
    const results = { created: 0, failed: 0 };

    // Process in batches to avoid overwhelming the database
    for (let i = 0; i < notificationData.userIds.length; i += this.BATCH_SIZE) {
      const batch = notificationData.userIds.slice(i, i + this.BATCH_SIZE);

      const batchPromises = batch.map(async (userId) => {
        try {
          await this.createNotification({
            ...notificationData,
            userId,
          });
          results.created++;
        } catch (error) {
          logger.error('Failed to create notification for user', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
          results.failed++;
        }
      });

      await Promise.allSettled(batchPromises);

      // Small delay between batches
      if (i + this.BATCH_SIZE < notificationData.userIds.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    logger.info('Bulk notifications created', {
      totalUsers: notificationData.userIds.length,
      created: results.created,
      failed: results.failed,
      type: notificationData.type,
    });

    return results;
  }

  /**
   * Get user notifications
   */
  public static async getUserNotifications(
    userId: string,
    filters: {
      type?: NotificationType;
      priority?: NotificationPriority;
      read?: boolean;
      limit?: number;
      offset?: number;
    } = {}
  ) {
    const { type, priority, read, limit = 50, offset = 0 } = filters;

    const where: any = {
      userId,
      OR: [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } },
      ],
    };

    if (type) where.type = type;
    if (priority) where.priority = priority;
    if (typeof read === 'boolean') where.read = read;

    const [notifications, total, unreadCount] = await Promise.all([
      prisma.notification.findMany({
        where,
        orderBy: [
          { priority: 'desc' },
          { createdAt: 'desc' },
        ],
        take: limit,
        skip: offset,
      }),
      prisma.notification.count({ where }),
      prisma.notification.count({
        where: {
          userId,
          read: false,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      }),
    ]);

    return {
      notifications,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + notifications.length < total,
      },
      unreadCount,
    };
  }

  /**
   * Mark notification as read
   */
  public static async markAsRead(
    notificationId: string,
    userId: string
  ): Promise<Notification> {
    return await prisma.$transaction(async (tx) => {
      const notification = await tx.notification.findFirst({
        where: {
          id: notificationId,
          userId,
        },
      });

      if (!notification) {
        throw new AppError('Notification not found', 404);
      }

      if (notification.read) {
        return notification;
      }

      const updatedNotification = await tx.notification.update({
        where: { id: notificationId },
        data: {
          read: true,
          readAt: new Date(),
        },
      });

      // Update cache
      await this.clearUserNotificationCache(userId);

      return updatedNotification;
    });
  }

  /**
   * Mark all notifications as read for a user
   */
  public static async markAllAsRead(userId: string): Promise<number> {
    const result = await prisma.notification.updateMany({
      where: {
        userId,
        read: false,
      },
      data: {
        read: true,
        readAt: new Date(),
      },
    });

    // Clear cache
    await this.clearUserNotificationCache(userId);

    logger.info('All notifications marked as read', {
      userId,
      count: result.count,
    });

    return result.count;
  }

  /**
   * Delete notification
   */
  public static async deleteNotification(
    notificationId: string,
    userId: string
  ): Promise<void> {
    const deleted = await prisma.notification.deleteMany({
      where: {
        id: notificationId,
        userId,
      },
    });

    if (deleted.count === 0) {
      throw new AppError('Notification not found', 404);
    }

    await this.clearUserNotificationCache(userId);

    logger.info('Notification deleted', {
      notificationId,
      userId,
    });
  }

  /**
   * Send election start notifications
   */
  public static async sendElectionStartNotifications(
    electionId: string
  ): Promise<{ sent: number; failed: number }> {
    const election = await prisma.election.findUnique({
      where: { id: electionId },
      include: {
        voterEligibility: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                phone: true,
                firstName: true,
                lastName: true,
              },
            },
          },
        },
      },
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    const userIds = election.voterEligibility.map(ve => ve.userId);

    const result = await this.createBulkNotifications({
      userIds,
      title: `Election Started: ${election.title}`,
      message: `The election "${election.title}" is now open for voting. Cast your vote before ${election.endDate.toLocaleString()}.`,
      type: 'ELECTION_STARTED',
      priority: 'HIGH',
      channels: ['email', 'sms', 'push'],
      actionUrl: `/elections/${electionId}/vote`,
      data: {
        electionId,
        electionTitle: election.title,
        endDate: election.endDate,
      },
    });

    return { sent: result.created, failed: result.failed };
  }

  /**
   * Send election reminder notifications
   */
  public static async sendElectionReminderNotifications(
    electionId: string,
    hoursRemaining: number
  ): Promise<{ sent: number; failed: number }> {
    const election = await prisma.election.findUnique({
      where: { id: electionId },
      include: {
        voterEligibility: {
          include: {
            user: true,
          },
        },
        votes: {
          select: { voterId: true },
        },
      },
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Get users who haven't voted yet
    const votedUserIds = new Set(election.votes.map(v => v.voterId));
    const unvotedUsers = election.voterEligibility
      .filter(ve => !votedUserIds.has(ve.userId))
      .map(ve => ve.userId);

    if (unvotedUsers.length === 0) {
      return { sent: 0, failed: 0 };
    }

    const result = await this.createBulkNotifications({
      userIds: unvotedUsers,
      title: `Reminder: ${election.title} - ${hoursRemaining} hours left`,
      message: `Don't miss your chance to vote in "${election.title}". Only ${hoursRemaining} hours remaining!`,
      type: 'ELECTION_ENDING',
      priority: 'MEDIUM',
      channels: ['email', 'sms', 'push'],
      actionUrl: `/elections/${electionId}/vote`,
      data: {
        electionId,
        electionTitle: election.title,
        hoursRemaining,
      },
    });

    return { sent: result.created, failed: result.failed };
  }

  /**
   * Send vote confirmation notifications
   */
  public static async sendVoteConfirmationNotification(
    userId: string,
    electionId: string,
    verificationCode: string,
    voteHash: string
  ): Promise<void> {
    const [user, election] = await Promise.all([
      prisma.user.findUnique({ where: { id: userId } }),
      prisma.election.findUnique({ where: { id: electionId } }),
    ]);

    if (!user || !election) {
      throw new AppError('User or election not found', 404);
    }

    const timestamp = new Date().toISOString();

    // Create in-app notification
    await this.createNotification({
      userId,
      title: 'Vote Confirmed',
      message: `Your vote in "${election.title}" has been successfully recorded.`,
      type: 'VOTE_CONFIRMED',
      priority: 'HIGH',
      channels: ['email', 'push'],
      data: {
        electionId,
        electionTitle: election.title,
        verificationCode,
        voteHash,
        timestamp,
      },
      actionUrl: `/elections/${electionId}/receipt`,
    });

    // Send enhanced email confirmation with PDF receipt
    await emailService.sendEnhancedVoteConfirmation(
      {
        email: user.email,
        firstName: user.firstName
      },
      {
        electionTitle: election.title,
        verificationCode,
        voteHash,
        timestamp,
        electionId
      }
    );

    logger.info(`Vote confirmation sent to ${user.email} for election ${election.title}`);
  }

  /**
   * Send result published notifications
   */
  public static async sendResultPublishedNotifications(
    electionId: string
  ): Promise<{ sent: number; failed: number }> {
    const election = await prisma.election.findUnique({
      where: { id: electionId },
      include: {
        votes: {
          select: { voterId: true },
          distinct: ['voterId'],
        },
        candidates: {
          select: { id: true, email: true },
        },
      },
    });

    if (!election) {
      throw new AppError('Election not found', 404);
    }

    // Notify all voters and candidates
    const voterIds = election.votes.map(v => v.voterId);
    const candidateEmails = election.candidates.map(c => c.email);

    // Get candidate user IDs
    const candidateUsers = await prisma.user.findMany({
      where: { email: { in: candidateEmails } },
      select: { id: true },
    });

    const allUserIds = [...new Set([...voterIds, ...candidateUsers.map(c => c.id)])];

    const result = await this.createBulkNotifications({
      userIds: allUserIds,
      title: `Results Published: ${election.title}`,
      message: `The results for "${election.title}" have been officially published.`,
      type: 'RESULT_PUBLISHED',
      priority: 'HIGH',
      channels: ['email', 'sms', 'push'],
      actionUrl: `/results/${electionId}`,
      data: {
        electionId,
        electionTitle: election.title,
      },
    });

    return { sent: result.created, failed: result.failed };
  }

  /**
   * Get notification statistics
   */
  public static async getNotificationStats(
    userId?: string
  ): Promise<NotificationStats> {
    const cacheKey = userId ? `notification-stats:${userId}` : 'notification-stats:global';
    const cached = await redis.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const where = userId ? { userId } : {};

    const [totalCount, unreadCount, typeStats, priorityStats, channelStats] = await Promise.all([
      prisma.notification.count({ where }),
      prisma.notification.count({ where: { ...where, read: false } }),
      // Get count by type
      prisma.notification.groupBy({
        by: ['type'],
        where,
        _count: true,
      }),
      // Get count by priority
      prisma.notification.groupBy({
        by: ['priority'],
        where,
        _count: true,
      }),
      // Get channel statistics
      prisma.notification.aggregate({
        where,
        _count: {
          emailSent: true,
          smsSent: true,
          pushSent: true,
        }
      }) as any,
    ]);

    const byType = {} as Record<NotificationType, number>;
    typeStats.forEach(stat => {
      byType[stat.type] = stat._count;
    });

    const byPriority = {} as Record<NotificationPriority, number>;
    priorityStats.forEach(stat => {
      byPriority[stat.priority] = stat._count;
    });

    const stats: NotificationStats = {
      total: totalCount,
      unread: unreadCount,
      byType,
      byPriority,
      byChannel: {
        email: {
          sent: (channelStats as any)._count?.emailSent || 0,
          failed: totalCount - ((channelStats as any)._count?.emailSent || 0),
        },
        sms: {
          sent: (channelStats as any)._count?.smsSent || 0,
          failed: totalCount - ((channelStats as any)._count?.smsSent || 0),
        },
        push: {
          sent: (channelStats as any)._count?.pushSent || 0,
          failed: totalCount - ((channelStats as any)._count?.pushSent || 0),
        },
      },
    };

    // Cache for 5 minutes
    await redis.setex(cacheKey, this.CACHE_TTL, JSON.stringify(stats));

    return stats;
  }

  /**
   * Deliver notification through specified channels (private method)
   */
  private static async deliverNotification(
    notification: Notification,
    user: { email: string; phone?: string | null; firstName: string; lastName: string }
  ): Promise<void> {
    const promises: Promise<boolean>[] = [];
    const channels = notification.channels as string[];

    // Email delivery
    if (channels.includes('email') && user.email) {
      promises.push(
        emailService.sendEmail({
          to: user.email,
          subject: notification.title,
          template: 'notification',
          data: {
            firstName: user.firstName,
            title: notification.title,
            message: notification.message,
            actionUrl: notification.actionUrl,
            priority: notification.priority,
          },
        })
      );
    }

    // SMS delivery
    if (channels.includes('sms') && user.phone) {
      const smsMessage = `${notification.title}\n${notification.message}`;
      promises.push(smsService.sendSMS({ to: user.phone, message: smsMessage }));
    }

    // Push notification delivery would go here
    if (channels.includes('push')) {
      // For now, just mark as "sent"
      promises.push(Promise.resolve(true));
    }

    // Execute all deliveries
    const results = await Promise.allSettled(promises);

    // Update notification with delivery status
    const updateData: any = {};

    if (channels.includes('email')) {
      updateData.emailSent = results[0]?.status === 'fulfilled' && results[0].value;
    }
    if (channels.includes('sms')) {
      const smsIndex = channels.includes('email') ? 1 : 0;
      updateData.smsSent = results[smsIndex]?.status === 'fulfilled' && results[smsIndex].value;
    }
    if (channels.includes('push')) {
      const pushIndex = channels.filter(c => ['email', 'sms'].includes(c)).length;
      updateData.pushSent = results[pushIndex]?.status === 'fulfilled' && results[pushIndex].value;
    }

    if (Object.keys(updateData).length > 0) {
      await prisma.notification.update({
        where: { id: notification.id },
        data: updateData,
      });
    }
  }

  /**
   * Cache notification for real-time updates
   */
  private static async cacheNotification(notification: Notification): Promise<void> {
    const cacheKey = `notification:${notification.userId}:${notification.id}`;
    await redis.setex(cacheKey, 3600, JSON.stringify(notification)); // 1 hour

    // Also update user's unread count cache
    await this.clearUserNotificationCache(notification.userId);
  }

  /**
   * Clear user notification cache
   */
  private static async clearUserNotificationCache(userId: string): Promise<void> {
    const patterns = [
      `notification:${userId}:*`,
      `notification-stats:${userId}`,
      `user-notifications:${userId}:*`,
    ];

    for (const pattern of patterns) {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }
  }

  /**
   * Clean up expired notifications
   */
  private static async cleanupExpiredNotifications(): Promise<void> {
    const deleted = await prisma.notification.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    logger.info('Expired notifications cleaned up', {
      deletedCount: deleted.count,
    });
  }


  /**
   * Send daily digest email to user
   */
  private static async sendDailyDigestEmail(userId: string, notifications: any[]): Promise<void> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { firstName: true, lastName: true, email: true },
      });

      if (!user) return;

      const digestContent = this.formatDigestContent(notifications);

      // Send via email provider (implementation would depend on your email service)
      logger.info(`📧 Daily digest email prepared for ${user.email}`);

      // Mark notifications as emailed
      await prisma.notification.updateMany({
        where: {
          id: { in: notifications.map(n => n.id) },
        },
        data: {
          emailSent: true,
        },
      });
    } catch (error) {
      logger.error('Error sending digest email:', error);
    }
  }

  /**
   * Format notifications into digest content
   */
  private static formatDigestContent(notifications: any[]): string {
    const groupedNotifications = notifications.reduce((acc, notification) => {
      const type = notification.type;
      if (!acc[type]) acc[type] = [];
      acc[type].push(notification);
      return acc;
    }, {} as Record<string, any[]>);

    let content = 'Daily Notification Summary:\n\n';

    Object.entries(groupedNotifications).forEach(([type, notifs]) => {
      const notifsArray = notifs as any[];
      content += `${type.replace('_', ' ').toUpperCase()}: ${notifsArray.length} notifications\n`;
      notifsArray.forEach((notif: any) => {
        content += `  - ${notif.title}: ${notif.message}\n`;
      });
      content += '\n';
    });

    return content;
  }

  /**
   * Send system-wide notification to users
   */
  public static async sendSystemNotification(options: {
    title: string;
    message: string;
    type: NotificationType;
    priority: NotificationPriority;
    targetAudience?: 'all' | 'voters' | 'admins';
    sentBy: string;
  }): Promise<{ recipientCount: number; sent: number; failed: number }> {
    try {
      const { title, message, type, priority, targetAudience = 'all', sentBy } = options;

      // Build user filter based on target audience
      const where: any = { isActive: true };
      if (targetAudience === 'voters') {
        where.role = 'VOTER';
      } else if (targetAudience === 'admins') {
        where.role = { in: ['ADMIN', 'SUPER_ADMIN', 'MODERATOR'] };
      }

      // Get target users
      const users = await prisma.user.findMany({
        where,
        select: { id: true, email: true, firstName: true },
      });

      let sent = 0;
      let failed = 0;

      // Send notifications in batches
      for (let i = 0; i < users.length; i += this.BATCH_SIZE) {
        const batch = users.slice(i, i + this.BATCH_SIZE);

        await Promise.allSettled(
          batch.map(async (user) => {
            try {
              await this.createNotification({
                userId: user.id,
                title,
                message,
                type,
                priority,
                channels: ['email', 'push'],
                data: { sentBy, targetAudience },
              });
              sent++;
            } catch (error) {
              logger.error('Failed to send system notification', { userId: user.id, error });
              failed++;
            }
          })
        );
      }

      logger.info('System notification sent', {
        title,
        targetAudience,
        recipientCount: users.length,
        sent,
        failed,
      });

      return {
        recipientCount: users.length,
        sent,
        failed,
      };
    } catch (error: any) {
      logger.error('Error sending system notification', error);
      throw new AppError('Failed to send system notification: ' + error.message, 500);
    }
  }

  /**
   * Stop all scheduled jobs
   */
  public static stopScheduledJobs(): void {
    this.scheduledJobs.forEach((job, name) => {
      job.stop();
      logger.info(`Stopped scheduled job: ${name}`);
    });
    this.scheduledJobs.clear();
  }
}

// Export singleton instance
export const notificationService = new NotificationService();
export default NotificationService;
