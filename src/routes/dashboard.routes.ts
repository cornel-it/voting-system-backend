import { Router } from 'express';
import { authenticate } from '../middleware/auth.middleware';
import { DashboardController } from '../controllers/dashboard.controller';

const router = Router();

// Voter dashboard
router.get('/voter', authenticate, DashboardController.getVoterDashboard);

// Candidate dashboard
router.get('/candidate', authenticate, DashboardController.getCandidateDashboard);

// Admin dashboard
router.get('/admin', authenticate, DashboardController.getAdminDashboard);

// Dashboard updates
router.get('/updates', authenticate, DashboardController.getDashboardUpdates);

// Refresh dashboard cache
router.post('/refresh', authenticate, DashboardController.refreshDashboardCache);

// Dashboard statistics
router.get('/stats', authenticate, DashboardController.getDashboardStats);

// Dashboard notifications
router.get('/notifications', authenticate, DashboardController.getDashboardNotifications);

// Export dashboard data
router.get('/export', authenticate, DashboardController.exportDashboardData);

export default router;