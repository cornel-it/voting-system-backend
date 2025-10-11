// backend/src/routes/election.routes.ts

import { Router } from 'express';
import { electionController } from '../controllers/election.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import {
  validateCreateElection,
  validateUpdateElection,
  validateElectionSearch
} from '../validators/election.validator';

const router = Router();

// Public routes (authenticated users)
router.get(
  '/',
  authenticate,
  validateElectionSearch,
  electionController.getElections.bind(electionController)
);

router.get(
  '/active',
  authenticate,
  electionController.getActiveElections.bind(electionController)
);

router.get(
  '/eligible',
  authenticate,
  electionController.getUserEligibleElections.bind(electionController)
);

router.get(
  '/:id',
  authenticate,
  electionController.getElectionById.bind(electionController)
);

// Admin routes
router.post(
  '/',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  validateCreateElection,
  electionController.createElection.bind(electionController)
);

router.put(
  '/:id',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  validateUpdateElection,
  electionController.updateElection.bind(electionController)
);

router.delete(
  '/:id',
  authenticate,
  authorize('SUPER_ADMIN'),
  electionController.deleteElection.bind(electionController)
);

router.post(
  '/:id/start',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.startElection.bind(electionController)
);

router.post(
  '/:id/end',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.endElection.bind(electionController)
);

router.post(
  '/:id/pause',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.pauseElection.bind(electionController)
);

router.post(
  '/:id/resume',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.resumeElection.bind(electionController)
);

router.post(
  '/:id/archive',
  authenticate,
  authorize('SUPER_ADMIN'),
  electionController.archiveElection.bind(electionController)
);

router.get(
  '/:id/stats',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.getElectionStats.bind(electionController)
);

router.post(
  '/:id/voters/add',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.addEligibleVoters.bind(electionController)
);

router.post(
  '/:id/voters/remove',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  electionController.removeEligibleVoters.bind(electionController)
);

export default router;
