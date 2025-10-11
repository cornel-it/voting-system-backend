// backend/src/websocket/index.ts

import { Server as SocketIOServer, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { prisma } from '../config/database';
import { redis } from '../config/redis';
import { logger } from '../utils/logger';
import { AppError } from '../utils/errors';

interface AuthenticatedSocket extends Socket {
  user?: {
    id: string;
    studentId: string;
    role: string;
    email: string;
  };
}

interface ElectionUpdate {
  electionId: string;
  type: 'VOTE_CAST' | 'RESULT_UPDATE' | 'STATUS_CHANGE' | 'TURNOUT_UPDATE';
  data: any;
  timestamp: Date;
}

interface NotificationData {
  userId: string;
  type: string;
  title: string;
  message: string;
  data?: any;
}

export class WebSocketService {
  private io: SocketIOServer;
  private connectedUsers: Map<string, Set<string>> = new Map(); // userId -> Set of socketIds
  private electionSubscriptions: Map<string, Set<string>> = new Map(); // electionId -> Set of socketIds

  constructor(io: SocketIOServer) {
    this.io = io;
    this.setupMiddleware();
    this.setupEventHandlers();
  }

  private setupMiddleware() {
    // Authentication middleware for WebSocket connections
    this.io.use(async (socket: AuthenticatedSocket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');

        if (!token) {
          // Allow anonymous connections for public data
          logger.info(`Anonymous WebSocket connection: ${socket.id}`);
          return next();
        }

        // Verify JWT token
        const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);

        // Get user from database
        const user = await prisma.user.findUnique({
          where: { id: decoded.userId },
          select: {
            id: true,
            studentId: true,
            email: true,
            role: true,
            isActive: true
          }
        });

        if (!user || !user.isActive) {
          throw new AppError('User not found or inactive', 401);
        }

        socket.user = user;
        logger.info(`Authenticated WebSocket connection: ${socket.id} (User: ${user.studentId})`);
        next();
      } catch (error) {
        logger.error('WebSocket authentication failed:', error);
        next(new Error('Authentication failed'));
      }
    });
  }

  private setupEventHandlers() {
    this.io.on('connection', (socket: AuthenticatedSocket) => {
      this.handleConnection(socket);

      // User-specific events
      socket.on('join:user', () => this.handleJoinUser(socket));
      socket.on('leave:user', () => this.handleLeaveUser(socket));

      // Election-specific events
      socket.on('join:election', (electionId: string) => this.handleJoinElection(socket, electionId));
      socket.on('leave:election', (electionId: string) => this.handleLeaveElection(socket, electionId));

      // Admin-specific events
      socket.on('join:admin', () => this.handleJoinAdmin(socket));
      socket.on('leave:admin', () => this.handleLeaveAdmin(socket));

      // Real-time vote tracking
      socket.on('subscribe:vote_updates', (electionId: string) => this.handleSubscribeVoteUpdates(socket, electionId));
      socket.on('unsubscribe:vote_updates', (electionId: string) => this.handleUnsubscribeVoteUpdates(socket, electionId));

      // Heartbeat for connection monitoring
      socket.on('ping', () => {
        socket.emit('pong', { timestamp: new Date().toISOString() });
      });

      // Disconnect handler
      socket.on('disconnect', (reason) => this.handleDisconnect(socket, reason));
    });
  }

  private handleConnection(socket: AuthenticatedSocket) {
    logger.info(`WebSocket client connected: ${socket.id}`);

    // Track user connections
    if (socket.user) {
      const userSockets = this.connectedUsers.get(socket.user.id) || new Set();
      userSockets.add(socket.id);
      this.connectedUsers.set(socket.user.id, userSockets);

      // Emit connection confirmation
      socket.emit('connection:confirmed', {
        socketId: socket.id,
        user: socket.user,
        timestamp: new Date().toISOString()
      });

      // Send any pending notifications
      this.sendPendingNotifications(socket);
    }

    // Send server status
    socket.emit('server:status', {
      online: true,
      timestamp: new Date().toISOString(),
      connectedUsers: this.connectedUsers.size
    });
  }

  private handleJoinUser(socket: AuthenticatedSocket) {
    if (!socket.user) return;

    socket.join(`user:${socket.user.id}`);
    logger.info(`User ${socket.user.studentId} joined personal channel`);

    socket.emit('joined:user', {
      userId: socket.user.id,
      timestamp: new Date().toISOString()
    });
  }

  private handleLeaveUser(socket: AuthenticatedSocket) {
    if (!socket.user) return;

    socket.leave(`user:${socket.user.id}`);
    logger.info(`User ${socket.user.studentId} left personal channel`);
  }

  private handleJoinElection(socket: AuthenticatedSocket, electionId: string) {
    if (!electionId) return;

    socket.join(`election:${electionId}`);

    // Track election subscriptions
    const electionSockets = this.electionSubscriptions.get(electionId) || new Set();
    electionSockets.add(socket.id);
    this.electionSubscriptions.set(electionId, electionSockets);

    logger.info(`Socket ${socket.id} joined election ${electionId}`);

    socket.emit('joined:election', {
      electionId,
      timestamp: new Date().toISOString()
    });

    // Send current election status
    this.sendElectionStatus(socket, electionId);
  }

  private handleLeaveElection(socket: AuthenticatedSocket, electionId: string) {
    if (!electionId) return;

    socket.leave(`election:${electionId}`);

    // Remove from election subscriptions
    const electionSockets = this.electionSubscriptions.get(electionId);
    if (electionSockets) {
      electionSockets.delete(socket.id);
      if (electionSockets.size === 0) {
        this.electionSubscriptions.delete(electionId);
      }
    }

    logger.info(`Socket ${socket.id} left election ${electionId}`);
  }

  private handleJoinAdmin(socket: AuthenticatedSocket) {
    if (!socket.user || !['ADMIN', 'SUPER_ADMIN'].includes(socket.user.role)) {
      socket.emit('error', { message: 'Insufficient permissions for admin channel' });
      return;
    }

    socket.join('admin:dashboard');
    logger.info(`Admin ${socket.user.studentId} joined admin channel`);

    socket.emit('joined:admin', {
      timestamp: new Date().toISOString()
    });

    // Send admin dashboard data
    this.sendAdminDashboardData(socket);
  }

  private handleLeaveAdmin(socket: AuthenticatedSocket) {
    socket.leave('admin:dashboard');
    logger.info(`Socket ${socket.id} left admin channel`);
  }

  private handleSubscribeVoteUpdates(socket: AuthenticatedSocket, electionId: string) {
    if (!electionId) return;

    socket.join(`votes:${electionId}`);
    logger.info(`Socket ${socket.id} subscribed to vote updates for election ${electionId}`);

    socket.emit('subscribed:vote_updates', {
      electionId,
      timestamp: new Date().toISOString()
    });
  }

  private handleUnsubscribeVoteUpdates(socket: AuthenticatedSocket, electionId: string) {
    if (!electionId) return;

    socket.leave(`votes:${electionId}`);
    logger.info(`Socket ${socket.id} unsubscribed from vote updates for election ${electionId}`);
  }

  private handleDisconnect(socket: AuthenticatedSocket, reason: string) {
    logger.info(`WebSocket client disconnected: ${socket.id} (${reason})`);

    // Clean up user connections
    if (socket.user) {
      const userSockets = this.connectedUsers.get(socket.user.id);
      if (userSockets) {
        userSockets.delete(socket.id);
        if (userSockets.size === 0) {
          this.connectedUsers.delete(socket.user.id);
        }
      }
    }

    // Clean up election subscriptions
    for (const [electionId, sockets] of this.electionSubscriptions.entries()) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        this.electionSubscriptions.delete(electionId);
      }
    }
  }

  // Public methods for broadcasting updates

  public async broadcastElectionUpdate(update: ElectionUpdate) {
    try {
      const { electionId, type, data, timestamp } = update;

      // Broadcast to election subscribers
      this.io.to(`election:${electionId}`).emit('election:update', {
        type,
        data,
        timestamp,
        electionId
      });

      // Broadcast vote updates to specific vote subscribers
      if (type === 'VOTE_CAST' || type === 'RESULT_UPDATE') {
        this.io.to(`votes:${electionId}`).emit('votes:update', {
          type,
          data,
          timestamp,
          electionId
        });
      }

      // Broadcast to admin dashboard
      this.io.to('admin:dashboard').emit('admin:election_update', {
        type,
        data,
        timestamp,
        electionId
      });

      logger.info(`Broadcasted election update: ${type} for election ${electionId}`);
    } catch (error) {
      logger.error('Error broadcasting election update:', error);
    }
  }

  public async sendNotificationToUser(notification: NotificationData) {
    try {
      const { userId, type, title, message, data } = notification;

      // Send to specific user
      this.io.to(`user:${userId}`).emit('notification', {
        type,
        title,
        message,
        data,
        timestamp: new Date().toISOString()
      });

      // Store notification in Redis for offline users
      await this.storeNotificationForUser(userId, notification);

      logger.info(`Sent notification to user ${userId}: ${type}`);
    } catch (error) {
      logger.error('Error sending notification to user:', error);
    }
  }

  public async broadcastSystemAnnouncement(announcement: {
    title: string;
    message: string;
    type: 'INFO' | 'WARNING' | 'MAINTENANCE';
    data?: any;
  }) {
    try {
      this.io.emit('system:announcement', {
        ...announcement,
        timestamp: new Date().toISOString()
      });

      logger.info(`Broadcasted system announcement: ${announcement.type}`);
    } catch (error) {
      logger.error('Error broadcasting system announcement:', error);
    }
  }

  public getConnectionStats() {
    return {
      totalConnections: this.io.sockets.sockets.size,
      authenticatedUsers: this.connectedUsers.size,
      electionSubscriptions: Array.from(this.electionSubscriptions.entries()).map(([electionId, sockets]) => ({
        electionId,
        subscriberCount: sockets.size
      }))
    };
  }

  // Private helper methods

  private async sendPendingNotifications(socket: AuthenticatedSocket) {
    if (!socket.user) return;

    try {
      const notifications = await redis.lrange(`notifications:${socket.user.id}`, 0, -1);

      for (const notification of notifications) {
        const parsedNotification = JSON.parse(notification);
        socket.emit('notification', parsedNotification);
      }

      // Clear notifications after sending
      if (notifications.length > 0) {
        await redis.del(`notifications:${socket.user.id}`);
      }
    } catch (error) {
      logger.error('Error sending pending notifications:', error);
    }
  }

  private async sendElectionStatus(socket: AuthenticatedSocket, electionId: string) {
    try {
      const election = await prisma.election.findUnique({
        where: { id: electionId },
        include: {
          _count: {
            select: {
              votes: true,
              candidates: true
            }
          }
        }
      });

      if (election) {
        socket.emit('election:status', {
          electionId,
          status: election.status,
          voteCount: election._count.votes,
          candidateCount: election._count.candidates,
          turnoutPercentage: election.turnoutPercentage,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      logger.error('Error sending election status:', error);
    }
  }

  private async sendAdminDashboardData(socket: AuthenticatedSocket) {
    try {
      const [totalUsers, totalElections, totalVotes, activeElections] = await Promise.all([
        prisma.user.count(),
        prisma.election.count(),
        prisma.vote.count(),
        prisma.election.count({ where: { status: 'ACTIVE' } })
      ]);

      socket.emit('admin:dashboard_data', {
        stats: {
          totalUsers,
          totalElections,
          totalVotes,
          activeElections
        },
        connections: this.getConnectionStats(),
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Error sending admin dashboard data:', error);
    }
  }

  private async storeNotificationForUser(userId: string, notification: NotificationData) {
    try {
      await redis.lpush(
        `notifications:${userId}`,
        JSON.stringify({
          ...notification,
          timestamp: new Date().toISOString()
        })
      );

      // Keep only last 50 notifications
      await redis.ltrim(`notifications:${userId}`, 0, 49);

      // Set expiry (7 days)
      await redis.expire(`notifications:${userId}`, 7 * 24 * 60 * 60);
    } catch (error) {
      logger.error('Error storing notification for user:', error);
    }
  }
}

// Export setup function
export function setupWebSocket(io: SocketIOServer): WebSocketService {
  const webSocketService = new WebSocketService(io);

  // Store service instance globally for access from other modules
  (global as any).webSocketService = webSocketService;

  logger.info('✅ WebSocket service initialized');

  return webSocketService;
}

// Export singleton getter
export function getWebSocketService(): WebSocketService | null {
  return (global as any).webSocketService || null;
}