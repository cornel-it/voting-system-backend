import { Router } from 'express';
import { authenticate } from '../middleware/auth.middleware';
import { ResultController } from '../controllers/result.controller';

const router = Router();

// Create controller instance (since ResultController uses instance methods)
const resultController = new ResultController();

// Calculate election results (Admin only)
router.post('/:electionId/calculate', authenticate, resultController.calculateResults.bind(resultController));

// Get election results
router.get('/:electionId', authenticate, resultController.getElectionResults.bind(resultController));

// Publish results (Admin only)
router.post('/:electionId/publish', authenticate, resultController.publishResults.bind(resultController));

// Get voting analytics (Admin/Moderator only)
router.get('/:electionId/analytics', authenticate, resultController.getVotingAnalytics.bind(resultController));

// Get live voting statistics
router.get('/:electionId/live-stats', authenticate, resultController.getLiveVotingStats.bind(resultController));

// Export results (Admin only)
router.get('/:electionId/export', authenticate, resultController.exportResults.bind(resultController));

// Get position-specific results
router.get('/:electionId/position/:positionId', authenticate, resultController.getPositionResults.bind(resultController));

// Get candidate performance (Admin only)
router.get('/:electionId/candidate/:candidateId/performance', authenticate, resultController.getCandidatePerformance.bind(resultController));

// Compare results between time periods (Admin only)
router.get('/:electionId/compare', authenticate, resultController.compareResults.bind(resultController));

// Verify results integrity (Super Admin only)
router.post('/:electionId/verify', authenticate, resultController.verifyResultsIntegrity.bind(resultController));

// Get result summary
router.get('/:electionId/summary', authenticate, resultController.getResultSummary.bind(resultController));

// Get historical comparison (Admin only)
router.get('/:electionId/historical-comparison', authenticate, resultController.getHistoricalComparison.bind(resultController));

// Generate results certificate (Admin only)
router.post('/:electionId/certificate', authenticate, resultController.generateResultsCertificate.bind(resultController));

export default router;
