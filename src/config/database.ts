import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

declare global {
  var prisma: PrismaClient | undefined;
}

class Database {
  private static instance: PrismaClient;

  private constructor() {}

  public static getInstance(): PrismaClient {
    if (!Database.instance) {
      Database.instance = new PrismaClient({
        log: process.env.NODE_ENV === 'development' 
          ? ['query', 'info', 'warn', 'error']
          : ['error'],
        errorFormat: 'minimal',
      });

      // Add middleware for soft deletes if needed
      Database.instance.$use(async (params, next) => {
        // Log slow queries in development
        if (process.env.NODE_ENV === 'development') {
          const before = Date.now();
          const result = await next(params);
          const after = Date.now();
          
          if (after - before > 100) {
            logger.warn(`Slow query: ${params.model}.${params.action} took ${after - before}ms`);
          }
          
          return result;
        }
        
        return next(params);
      });

      // Handle connection events
      Database.instance.$connect()
        .then(() => {
          logger.info('Database connected successfully');
        })
        .catch((error) => {
          logger.error('Failed to connect to database:', error);
          process.exit(1);
        });

      // Graceful shutdown
      process.on('SIGINT', async () => {
        await Database.instance.$disconnect();
        logger.info('Database disconnected');
        process.exit(0);
      });

      process.on('SIGTERM', async () => {
        await Database.instance.$disconnect();
        logger.info('Database disconnected');
        process.exit(0);
      });
    }

    return Database.instance;
  }

  public static async connect(): Promise<void> {
    try {
      const prisma = Database.getInstance();
      await prisma.$connect();
      logger.info('Database connection established');
    } catch (error) {
      logger.error('Database connection failed:', error);
      throw error;
    }
  }

  public static async disconnect(): Promise<void> {
    try {
      if (Database.instance) {
        await Database.instance.$disconnect();
        logger.info('Database disconnected');
      }
    } catch (error) {
      logger.error('Error disconnecting from database:', error);
      throw error;
    }
  }

  public static async healthCheck(): Promise<boolean> {
    try {
      const prisma = Database.getInstance();
      await prisma.$queryRaw`SELECT 1`;
      return true;
    } catch (error) {
      logger.error('Database health check failed:', error);
      return false;
    }
  }

  public static async runInTransaction<T>(
    fn: (prisma: PrismaClient) => Promise<T>
  ): Promise<T> {
    const prisma = Database.getInstance();
    return prisma.$transaction(async (tx) => {
      return fn(tx as PrismaClient);
    });
  }
}

// Export singleton instance
export const prisma = Database.getInstance();

// Export Database class for additional methods
export default Database;

// Global prisma instance for development
if (process.env.NODE_ENV !== 'production') {
  global.prisma = prisma;
}