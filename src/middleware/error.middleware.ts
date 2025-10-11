import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/errors';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'error',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

/**
 * Global error handler middleware
 */
export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let error = { ...err } as any;
  error.message = err.message;

  // Log error
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userId: (req as any).user?.id
  });

  // Prisma errors
  if (err instanceof PrismaClientKnownRequestError) {
    switch (err.code) {
      case 'P2002':
        // Unique constraint violation
        const field = (err.meta?.target as string[])?.[0];
        error = new AppError(
          `${field ? field + ' already exists' : 'Duplicate field value'}`,
          409
        );
        break;
      case 'P2025':
        // Record not found
        error = new AppError('Record not found', 404);
        break;
      case 'P2003':
        // Foreign key constraint violation
        error = new AppError('Related record not found', 400);
        break;
      default:
        error = new AppError('Database operation failed', 500);
    }
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token', 401);
  }

  if (err.name === 'TokenExpiredError') {
    error = new AppError('Token has expired', 401);
  }

  // Validation errors from express-validator
  if (err.name === 'ValidationError') {
    const errors = Object.values((err as any).errors).map((e: any) => e.message);
    error = new AppError('Validation failed', 400, 'VALIDATION_ERROR', errors);
  }

  // Multer file upload errors
  if (err.name === 'MulterError') {
    switch ((err as any).code) {
      case 'LIMIT_FILE_SIZE':
        error = new AppError('File too large', 400);
        break;
      case 'LIMIT_FILE_COUNT':
        error = new AppError('Too many files', 400);
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        error = new AppError('Unexpected field', 400);
        break;
      default:
        error = new AppError('File upload failed', 400);
    }
  }

  // Send error response
  res.status(error.statusCode || 500).json({
    success: false,
    error: {
      message: error.message || 'Server Error',
      statusCode: error.statusCode || 500,
      ...(process.env.NODE_ENV === 'development' && { 
        stack: err.stack,
        details: error.details 
      })
    }
  });
};

/**
 * Not found error handler
 */
export const notFound = (req: Request, res: Response, next: NextFunction) => {
  const error = new AppError(`Route not found - ${req.originalUrl}`, 404);
  next(error);
};

/**
 * Async error wrapper
 */
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};