// backend/src/routes/auth.routes.ts

import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { authRateLimit, generalRateLimit, passwordResetRateLimit } from '../middleware/rateLimit.middleware';
import { body, param } from 'express-validator';

const router = Router();

// Public routes
router.post('/register',
  authRateLimit,
  [
    body('studentId').notEmpty().matches(/^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/).withMessage('Invalid student ID format'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('firstName').notEmpty().isString().trim().withMessage('First name is required'),
    body('lastName').notEmpty().isString().trim().withMessage('Last name is required'),
  ],
  AuthController.register
);

router.post('/login',
  authRateLimit,
  [
    body('identifier').notEmpty().withMessage('Email or student ID is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  AuthController.login
);

router.post('/logout',
  authenticate,
  AuthController.logout
);

router.post('/refresh-token',
  generalRateLimit,
  [
    body('refreshToken').notEmpty().withMessage('Refresh token is required'),
  ],
  AuthController.refreshToken
);

router.get('/verify-email/:token',
  generalRateLimit,
  [
    param('token').notEmpty().isString().withMessage('Verification token is required'),
  ],
  AuthController.verifyEmail
);

router.post('/resend-verification',
  generalRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  ],
  AuthController.resendVerificationEmail
);

router.post('/password-reset/request',
  passwordResetRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  ],
  AuthController.requestPasswordReset
);

router.post('/password-reset/confirm',
  passwordResetRateLimit,
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ],
  AuthController.resetPassword
);

router.get('/account-status/:identifier',
  generalRateLimit,
  [
    param('identifier').notEmpty().withMessage('Identifier is required'),
  ],
  AuthController.getAccountStatus
);

// Protected routes (require authentication)
router.get('/profile',
  authenticate,
  AuthController.getProfile
);

router.put('/profile',
  authenticate,
  [
    body('firstName').optional().isString().trim().withMessage('First name must be a string'),
    body('lastName').optional().isString().trim().withMessage('Last name must be a string'),
    body('phone').optional().isMobilePhone('any').withMessage('Invalid phone number'),
  ],
  AuthController.updateProfile
);

router.post('/change-password',
  authenticate,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters'),
  ],
  AuthController.changePassword
);

router.post('/2fa/setup',
  authenticate,
  generalRateLimit,
  AuthController.setup2FA
);

router.post('/2fa/verify',
  authenticate,
  generalRateLimit,
  [
    body('token').notEmpty().withMessage('2FA token is required'),
  ],
  AuthController.verify2FA
);

router.post('/2fa/disable',
  authenticate,
  generalRateLimit,
  [
    body('token').notEmpty().withMessage('2FA token is required'),
  ],
  AuthController.disable2FA
);

router.get('/sessions',
  authenticate,
  AuthController.getActiveSessions
);

router.delete('/sessions/:sessionId',
  authenticate,
  [
    param('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
  ],
  AuthController.revokeSession
);

export default router;
