import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define log colors
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(colors);

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Define console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}${info.stack ? '\n' + info.stack : ''}`
  )
);

// Define transports
const transports = [
  // Console transport
  new winston.transports.Console({
    format: process.env.NODE_ENV === 'development' ? consoleFormat : format,
  }),
  
  // Error log file
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    maxsize: 10485760, // 10MB
    maxFiles: 5,
  }),
  
  // Combined log file
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    maxsize: 10485760, // 10MB
    maxFiles: 5,
  }),
];

// Add audit log transport for production
if (process.env.NODE_ENV === 'production') {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      level: 'info',
      maxsize: 10485760, // 10MB
      maxFiles: 10,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    })
  );
}

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'development' ? 'debug' : 'info'),
  levels,
  format,
  transports,
  exitOnError: false,
});

// Create stream for Morgan HTTP logging
export const stream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

// Helper functions for structured logging
export const logError = (error: Error, context?: Record<string, any>) => {
  logger.error({
    message: error.message,
    stack: error.stack,
    ...context,
  });
};

export const logAudit = (action: string, userId: string, details: Record<string, any>) => {
  logger.info({
    type: 'AUDIT',
    action,
    userId,
    timestamp: new Date().toISOString(),
    ...details,
  });
};

export const logSecurity = (event: string, severity: 'low' | 'medium' | 'high' | 'critical', details: Record<string, any>) => {
  const level = severity === 'critical' || severity === 'high' ? 'error' : 'warn';
  logger[level]({
    type: 'SECURITY',
    event,
    severity,
    timestamp: new Date().toISOString(),
    ...details,
  });
};

export const logPerformance = (operation: string, duration: number, details?: Record<string, any>) => {
  const level = duration > 1000 ? 'warn' : 'debug';
  logger[level]({
    type: 'PERFORMANCE',
    operation,
    duration,
    timestamp: new Date().toISOString(),
    ...details,
  });
};

// Export logger instance
export { logger };

// Default export
export default logger;