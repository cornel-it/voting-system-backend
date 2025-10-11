import Redis from 'ioredis';
import { logger } from '../utils/logger';

class RedisClient {
  private static instance: Redis;
  private static subscriber: Redis;
  private static publisher: Redis;

  private constructor() {}

  public static getInstance(): Redis {
    if (!RedisClient.instance) {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const redisPassword = process.env.REDIS_PASSWORD;
      const redisHost = process.env.REDIS_HOST;
      const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT) : 6379;
      const redisUsername = process.env.REDIS_USERNAME;

      const options: any = {
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: false,
        // Cloud Redis specific configurations
        connectTimeout: 10000,
        commandTimeout: 5000,
        // TLS support for cloud providers
        tls: redisUrl.includes('rediss://') || (redisHost && redisHost.includes('redis-cloud.com')) ? {} : undefined,
      };

      // Configure authentication
      if (redisPassword) {
        options.password = redisPassword;
      }

      if (redisUsername) {
        options.username = redisUsername;
      }

      // Use URL if provided, otherwise use host/port
      if (redisUrl && redisUrl !== 'redis://localhost:6379') {
        RedisClient.instance = new Redis(redisUrl, options);
      } else if (redisHost) {
        RedisClient.instance = new Redis({
          host: redisHost,
          port: redisPort,
          ...options
        });
      } else {
        RedisClient.instance = new Redis(redisUrl, options);
      }

      RedisClient.instance.on('connect', () => {
        logger.info('Redis client connected');
      });

      RedisClient.instance.on('error', (error) => {
        logger.error('Redis client error:', error);
      });

      RedisClient.instance.on('ready', () => {
        logger.info('Redis client ready');
      });
    }

    return RedisClient.instance;
  }

  public static getSubscriber(): Redis {
    if (!RedisClient.subscriber) {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const redisPassword = process.env.REDIS_PASSWORD;
      const redisHost = process.env.REDIS_HOST;
      const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT) : 6379;
      const redisUsername = process.env.REDIS_USERNAME;

      const options: any = {
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        connectTimeout: 10000,
        commandTimeout: 5000,
        tls: redisUrl.includes('rediss://') || (redisHost && redisHost.includes('redis-cloud.com')) ? {} : undefined,
      };

      if (redisPassword) {
        options.password = redisPassword;
      }

      if (redisUsername) {
        options.username = redisUsername;
      }

      if (redisUrl && redisUrl !== 'redis://localhost:6379') {
        RedisClient.subscriber = new Redis(redisUrl, options);
      } else if (redisHost) {
        RedisClient.subscriber = new Redis({
          host: redisHost,
          port: redisPort,
          ...options
        });
      } else {
        RedisClient.subscriber = new Redis(redisUrl, options);
      }

      RedisClient.subscriber.on('connect', () => {
        logger.info('Redis subscriber connected');
      });

      RedisClient.subscriber.on('error', (error) => {
        logger.error('Redis subscriber error:', error);
      });
    }

    return RedisClient.subscriber;
  }

  public static getPublisher(): Redis {
    if (!RedisClient.publisher) {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const redisPassword = process.env.REDIS_PASSWORD;
      const redisHost = process.env.REDIS_HOST;
      const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT) : 6379;
      const redisUsername = process.env.REDIS_USERNAME;

      const options: any = {
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        connectTimeout: 10000,
        commandTimeout: 5000,
        tls: redisUrl.includes('rediss://') || (redisHost && redisHost.includes('redis-cloud.com')) ? {} : undefined,
      };

      if (redisPassword) {
        options.password = redisPassword;
      }

      if (redisUsername) {
        options.username = redisUsername;
      }

      if (redisUrl && redisUrl !== 'redis://localhost:6379') {
        RedisClient.publisher = new Redis(redisUrl, options);
      } else if (redisHost) {
        RedisClient.publisher = new Redis({
          host: redisHost,
          port: redisPort,
          ...options
        });
      } else {
        RedisClient.publisher = new Redis(redisUrl, options);
      }

      RedisClient.publisher.on('connect', () => {
        logger.info('Redis publisher connected');
      });

      RedisClient.publisher.on('error', (error) => {
        logger.error('Redis publisher error:', error);
      });
    }

    return RedisClient.publisher;
  }

  public static async disconnect(): Promise<void> {
    if (RedisClient.instance) {
      await RedisClient.instance.quit();
    }
    if (RedisClient.subscriber) {
      await RedisClient.subscriber.quit();
    }
    if (RedisClient.publisher) {
      await RedisClient.publisher.quit();
    }
  }

  /**
   * Cache utility methods
   */
  public static async setCache(
    key: string,
    value: any,
    ttl: number = 3600
  ): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.setex(key, ttl, JSON.stringify(value));
  }

  public static async getCache<T>(key: string): Promise<T | null> {
    const redis = RedisClient.getInstance();
    const value = await redis.get(key);
    return value ? JSON.parse(value) : null;
  }

  public static async deleteCache(pattern: string): Promise<void> {
    const redis = RedisClient.getInstance();
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  }

  /**
   * Session management
   */
  public static async createSession(
    sessionId: string,
    userId: string,
    data: any,
    ttl: number = 3600
  ): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.setex(
      `session:${sessionId}`,
      ttl,
      JSON.stringify({ userId, ...data })
    );
  }

  public static async getSession(sessionId: string): Promise<any | null> {
    const redis = RedisClient.getInstance();
    const session = await redis.get(`session:${sessionId}`);
    return session ? JSON.parse(session) : null;
  }

  public static async deleteSession(sessionId: string): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.del(`session:${sessionId}`);
  }

  /**
   * Token blacklisting
   */
  public static async blacklistToken(
    token: string,
    ttl: number = 86400
  ): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.setex(`blacklist:${token}`, ttl, '1');
  }

  public static async isTokenBlacklisted(token: string): Promise<boolean> {
    const redis = RedisClient.getInstance();
    const result = await redis.get(`blacklist:${token}`);
    return result === '1';
  }

  /**
   * Rate limiting
   */
  public static async incrementRateLimit(
    key: string,
    window: number = 60
  ): Promise<number> {
    const redis = RedisClient.getInstance();
    const multi = redis.multi();
    multi.incr(key);
    multi.expire(key, window);
    const results = await multi.exec();
    return results ? results[0][1] as number : 0;
  }

  /**
   * Distributed locking
   */
  public static async acquireLock(
    resource: string,
    ttl: number = 10
  ): Promise<boolean> {
    const redis = RedisClient.getInstance();
    const lockKey = `lock:${resource}`;
    const lockValue = `${Date.now()}-${Math.random()}`;
    
    const result = await redis.set(
      lockKey,
      lockValue,
      'EX',
      ttl,
      'NX'
    );
    
    return result === 'OK';
  }

  public static async releaseLock(resource: string): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.del(`lock:${resource}`);
  }

  /**
   * Queue management
   */
  public static async pushToQueue(
    queueName: string,
    data: any
  ): Promise<void> {
    const redis = RedisClient.getInstance();
    await redis.lpush(`queue:${queueName}`, JSON.stringify(data));
  }

  public static async popFromQueue(queueName: string): Promise<any | null> {
    const redis = RedisClient.getInstance();
    const data = await redis.rpop(`queue:${queueName}`);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Pub/Sub helpers
   */
  public static async publish(channel: string, message: any): Promise<void> {
    const publisher = RedisClient.getPublisher();
    await publisher.publish(channel, JSON.stringify(message));
  }

  public static async subscribe(
    channel: string,
    callback: (message: any) => void
  ): Promise<void> {
    const subscriber = RedisClient.getSubscriber();
    await subscriber.subscribe(channel);
    
    subscriber.on('message', (receivedChannel, message) => {
      if (receivedChannel === channel) {
        try {
          const parsed = JSON.parse(message);
          callback(parsed);
        } catch (error) {
          logger.error('Failed to parse message:', error);
        }
      }
    });
  }

  public static async unsubscribe(channel: string): Promise<void> {
    const subscriber = RedisClient.getSubscriber();
    await subscriber.unsubscribe(channel);
  }
}

// Export singleton instance
export const redis = RedisClient.getInstance();
export const redisSubscriber = RedisClient.getSubscriber();
export const redisPublisher = RedisClient.getPublisher();

// Export utility functions
export const {
  setCache,
  getCache,
  deleteCache,
  createSession,
  getSession,
  deleteSession,
  blacklistToken,
  isTokenBlacklisted,
  incrementRateLimit,
  acquireLock,
  releaseLock,
  pushToQueue,
  popFromQueue,
  publish,
  subscribe,
  unsubscribe,
} = RedisClient;

export default RedisClient;