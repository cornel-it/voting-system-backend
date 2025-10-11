// backend/src/routes/index.ts

import { Router } from 'express';
import { authenticate, optionalAuth } from '../middleware/auth.middleware';
import { logger } from '../utils/logger';

// Import route modules
import authRoutes from './auth.routes';
import electionRoutes from './election.routes';
import candidateRoutes from './candidate.routes';
import voteRoutes from './vote.routes';
import resultRoutes from './result.routes';
import voterRoutes from './voter.routes';
import adminRoutes from './admin.routes';
import auditRoutes from './audit.routes';
import reportRoutes from './report.routes';

const router = Router();

// API versioning and health check
router.get('/', (req, res) => {
  res.json({
    message: 'JKUAT Voting System API',
    version: '1.0.0',
    status: 'operational',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth',
      elections: '/api/elections',
      candidates: '/api/candidates',
      votes: '/api/votes',
      results: '/api/results',
      voters: '/api/voters',
      admin: '/api/admin',
      audit: '/api/audit',
      reports: '/api/reports'
    },
    documentation: '/api/docs',
    health: '/health'
  });
});

// Request logging middleware
router.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };

    if (res.statusCode >= 400) {
      logger.warn('API Request Error:', logData);
    } else {
      logger.info('API Request:', logData);
    }
  });

  next();
});

// Authentication routes (public)
router.use('/auth', authRoutes);

// Election routes (mixed public/protected)
router.use('/elections', electionRoutes);

// Results routes (mixed public/protected)
router.use('/results', resultRoutes);

// Protected routes - require authentication
router.use('/candidates', authenticate, candidateRoutes);
router.use('/votes', authenticate, voteRoutes);
router.use('/voters', authenticate, voterRoutes);
router.use('/admin', authenticate, adminRoutes);
router.use('/audit', authenticate, auditRoutes);
router.use('/reports', authenticate, reportRoutes);

// API documentation route (if using Swagger or similar)
router.get('/docs', (req, res) => {
  res.json({
    message: 'API Documentation',
    swagger: '/api/swagger.json',
    postman: '/api/postman.json',
    openapi: '/api/openapi.json'
  });
});

// API statistics endpoint
router.get('/stats', optionalAuth, async (req, res) => {
  try {
    // This could be enhanced to show real statistics
    const stats = {
      api_version: '1.0.0',
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      environment: process.env.NODE_ENV,
      endpoints_count: 75, // Approximate - increased with audit and report routes
      last_updated: new Date().toISOString()
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error fetching API stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch API statistics'
    });
  }
});

// Catch-all for undefined API routes
router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'API endpoint not found',
    message: `Route ${req.method} ${req.originalUrl} does not exist`,
    available_endpoints: [
      'GET /api/',
      'POST /api/auth/login',
      'POST /api/auth/register',
      'GET /api/elections',
      'GET /api/results/:electionId',
      'POST /api/votes/cast',
      'GET /api/admin/dashboard',
      'GET /api/audit/logs',
      'GET /api/reports/election/:electionId',
      'GET /api/reports/system',
      'GET /api/health'
    ]
  });
});

export default router;