// backend/src/services/websocket.service.ts

import { Server as HttpServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { logger } from '../utils/logger';
import { redis } from '../config/redis';
import { UserRole } from '@prisma/client';
import { prisma } from '../config/database';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  userRole?: UserRole;
}

export class WebSocketService {
  private static instance: WebSocketService;
  private io: SocketIOServer | null = null;
  private activeConnections: Map<string, AuthenticatedSocket> = new Map();

  private constructor() {}

  public static getInstance(): WebSocketService {
    if (!WebSocketService.instance) {
      WebSocketService.instance = new WebSocketService();
    }
    return WebSocketService.instance;
  }

  public initialize(server: HttpServer): void {
    this.io = new SocketIOServer(server, {
      cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        methods: ["GET", "POST"],
        credentials: true,
      },
      transports: ['websocket', 'polling'],
    });

    this.io.on('connection', (socket: AuthenticatedSocket) => {
      logger.info(`🔌 Client connected: ${socket.id}`);
      this.handleConnection(socket);
    });

    // Start periodic update broadcasts
    this.startPeriodicUpdates();

    logger.info('🚀 WebSocket service initialized');
  }

  private async handleConnection(socket: AuthenticatedSocket): Promise<void> {
    // Handle authentication
    socket.on('authenticate', async (data: { token: string }) => {
      try {
        const user = await this.authenticateSocket(data.token);
        if (user) {
          socket.userId = user.id;
          socket.userRole = user.role;
          this.activeConnections.set(user.id, socket);

          // Join role-based rooms
          socket.join(`role:${user.role}`);
          socket.join(`user:${user.id}`);

          socket.emit('authenticated', { userId: user.id, role: user.role });
          logger.info(`✅ Socket authenticated: ${user.id} (${user.role})`);
        } else {
          socket.emit('authentication_failed');
          socket.disconnect();
        }
      } catch (error) {
        logger.error('Socket authentication error:', error);
        socket.emit('authentication_failed');
        socket.disconnect();
      }
    });

    // Handle dashboard subscription
    socket.on('subscribe_dashboard', async () => {
      if (!socket.userId) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      socket.join(`dashboard:${socket.userId}`);

      // Send initial dashboard updates
      const updates = await this.getDashboardUpdates(socket.userId, socket.userRole!);
      socket.emit('dashboard_updates', updates);
    });

    // Handle election subscription
    socket.on('subscribe_election', (data: { electionId: string }) => {
      if (!socket.userId) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      socket.join(`election:${data.electionId}`);
      logger.info(`📊 User ${socket.userId} subscribed to election ${data.electionId}`);
    });

    // Handle voting session subscription
    socket.on('subscribe_voting', (data: { sessionId: string }) => {
      if (!socket.userId) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      socket.join(`voting:${data.sessionId}`);
      logger.info(`🗳️ User ${socket.userId} subscribed to voting session ${data.sessionId}`);
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      if (socket.userId) {
        this.activeConnections.delete(socket.userId);
        logger.info(`🔌 Client disconnected: ${socket.userId}`);
      }
    });
  }

  private async authenticateSocket(token: string): Promise<{ id: string; role: UserRole } | null> {
    try {
      // Import JWT and auth service
      const jwt = require('jsonwebtoken');
      const { authService } = await import('./auth.service');

      // Extract token from Bearer format if needed
      const cleanToken = token.replace('Bearer ', '');

      // Verify JWT token
      let decoded;
      try {
        decoded = jwt.verify(cleanToken, process.env.JWT_SECRET || 'your-secret-key');
      } catch (jwtError) {
        logger.error('JWT verification failed:', jwtError);
        return null;
      }

      const userId = decoded.userId || decoded.sub;
      if (!userId) {
        logger.error('No userId found in JWT token');
        return null;
      }

      // Check Redis for cached session first
      const cachedSession = await redis.get(`session:${cleanToken}`);
      if (cachedSession) {
        const session = JSON.parse(cachedSession);
        return { id: session.userId, role: session.role };
      }

      // Verify user exists and is active
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          role: true,
          isActive: true,
          isVerified: true,
        },
      });

      if (!user || !user.isActive) {
        logger.error(`User not found or inactive: ${userId}`);
        return null;
      }

      // Cache the session for 1 hour
      await redis.setex(`session:${cleanToken}`, 3600, JSON.stringify({
        userId: user.id,
        role: user.role,
        isVerified: user.isVerified,
      }));

      return { id: user.id, role: user.role };
    } catch (error) {
      logger.error('Socket authentication error:', error);
      return null;
    }
  }

  // Real-time update methods
  public async broadcastElectionUpdate(electionId: string, update: any): Promise<void> {
    if (!this.io) return;

    this.io.to(`election:${electionId}`).emit('election_update', {
      electionId,
      type: 'election_status_change',
      data: update,
      timestamp: new Date(),
    });

    logger.info(`📡 Broadcasted election update for ${electionId}`);
  }

  public async broadcastVoteUpdate(sessionId: string, update: any): Promise<void> {
    if (!this.io) return;

    this.io.to(`voting:${sessionId}`).emit('vote_update', {
      sessionId,
      type: 'vote_progress',
      data: update,
      timestamp: new Date(),
    });
  }

  public async broadcastResultUpdate(electionId: string, results: any): Promise<void> {
    if (!this.io) return;

    this.io.to(`election:${electionId}`).emit('results_update', {
      electionId,
      type: 'results_published',
      data: results,
      timestamp: new Date(),
    });

    logger.info(`📊 Broadcasted results for election ${electionId}`);
  }

  public async sendUserNotification(userId: string, notification: any): Promise<void> {
    if (!this.io) return;

    this.io.to(`user:${userId}`).emit('notification', {
      ...notification,
      timestamp: new Date(),
    });
  }

  public async broadcastSystemAlert(alert: any): Promise<void> {
    if (!this.io) return;

    // Send to admin users
    this.io.to('role:ADMIN').to('role:SUPER_ADMIN').emit('system_alert', {
      ...alert,
      timestamp: new Date(),
    });

    logger.info(`🚨 Broadcasted system alert: ${alert.title}`);
  }

  // Dashboard-specific updates
  public async getDashboardUpdates(userId: string, userRole: UserRole): Promise<any> {
    const updates = [];
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    if (userRole === 'VOTER') {
      // Get voter-specific updates
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { faculty: true, department: true, course: true, yearOfStudy: true },
      });

      if (user) {
        const newElections = await prisma.election.count({
          where: {
            createdAt: { gte: oneHourAgo },
            OR: [
              { eligibleFaculties: { has: user.faculty } },
              { eligibleDepartments: { has: user.department } },
              { eligibleCourses: { has: user.course } },
              { eligibleYears: { has: user.yearOfStudy } },
            ],
          },
        });

        if (newElections > 0) {
          updates.push({
            type: 'new_elections',
            message: `${newElections} new election(s) available`,
            count: newElections,
          });
        }
      }
    } else if (userRole === 'ADMIN' || userRole === 'SUPER_ADMIN') {
      // Get admin-specific updates
      const pendingCandidates = await prisma.candidate.count({
        where: {
          status: 'PENDING',
          createdAt: { gte: oneHourAgo },
        },
      });

      if (pendingCandidates > 0) {
        updates.push({
          type: 'pending_approvals',
          message: `${pendingCandidates} candidate(s) need approval`,
          count: pendingCandidates,
        });
      }
    }

    return updates;
  }

  private startPeriodicUpdates(): void {
    // Send dashboard updates every 30 seconds
    setInterval(async () => {
      try {
        for (const [userId, socket] of this.activeConnections) {
          if (socket.userRole) {
            const updates = await this.getDashboardUpdates(userId, socket.userRole);
            if (updates.length > 0) {
              socket.emit('dashboard_updates', updates);
            }
          }
        }
      } catch (error) {
        logger.error('Error sending periodic updates:', error);
      }
    }, 30000);

    // Send system health updates every 5 minutes for admins
    setInterval(async () => {
      try {
        const healthStatus = await this.getSystemHealth();
        this.io?.to('role:ADMIN').to('role:SUPER_ADMIN').emit('system_health', healthStatus);
      } catch (error) {
        logger.error('Error sending health updates:', error);
      }
    }, 300000);
  }

  private async getSystemHealth(): Promise<any> {
    try {
      // Basic health check
      const dbStart = Date.now();
      await prisma.$queryRaw`SELECT 1`;
      const dbResponseTime = Date.now() - dbStart;

      let redisStatus = 'connected';
      try {
        await redis.ping();
      } catch {
        redisStatus = 'disconnected';
      }

      return {
        database: { responseTime: dbResponseTime, status: 'connected' },
        redis: { status: redisStatus },
        uptime: process.uptime(),
        memory: Math.round((process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100),
        activeConnections: this.activeConnections.size,
      };
    } catch (error) {
      return { status: 'error', error: error instanceof Error ? error.message : String(error) };
    }
  }

  // Utility methods
  public getActiveConnections(): number {
    return this.activeConnections.size;
  }

  public getUserConnectionStatus(userId: string): boolean {
    return this.activeConnections.has(userId);
  }

  public async disconnectUser(userId: string): Promise<void> {
    const socket = this.activeConnections.get(userId);
    if (socket) {
      socket.disconnect();
      this.activeConnections.delete(userId);
    }
  }
}

// Export singleton instance
export const webSocketService = WebSocketService.getInstance();
export default webSocketService;