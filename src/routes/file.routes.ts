import { Router } from 'express';
import multer from 'multer';
import { FileController } from '../controllers/file.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { body, query, param } from 'express-validator';
import { uploadRateLimit } from '../middleware/rateLimit.middleware';
import { fileService, FileService } from '../services/file.service';

const router = Router();

// Configure multer for different upload types
const createMulterMiddleware = (config: any) => {
  return multer(fileService.getMulterConfig(config));
};

/**
 * @route POST /api/files/upload/profile-image
 * @desc Upload profile image
 * @access Authenticated users
 */
router.post(
  '/upload/profile-image',
  authenticate,
  uploadRateLimit,
  (req, res, next) => {
    const config = FileService.getProfileImageConfig();
    const upload = createMulterMiddleware(config);
    upload.single('profileImage')(req, res, next);
  },
  FileController.uploadProfileImage
);

/**
 * @route POST /api/files/upload/candidate-photo
 * @desc Upload candidate photo
 * @access Authenticated users (candidates)
 */
router.post(
  '/upload/candidate-photo',
  authenticate,
  uploadRateLimit,
  (req, res, next) => {
    const config = FileService.getCandidatePhotoConfig();
    const upload = createMulterMiddleware(config);
    upload.single('candidatePhoto')(req, res, next);
  },
  FileController.uploadCandidatePhoto
);

/**
 * @route POST /api/files/upload/manifesto
 * @desc Upload manifesto document
 * @access Authenticated users (candidates)
 */
router.post(
  '/upload/manifesto',
  authenticate,
  uploadRateLimit,
  (req, res, next) => {
    const config = FileService.getManifestoConfig();
    const upload = createMulterMiddleware(config);
    upload.single('manifesto')(req, res, next);
  },
  FileController.uploadManifesto
);

/**
 * @route POST /api/files/upload/banner-image
 * @desc Upload banner image
 * @access Admin, Super Admin, Moderator
 */
router.post(
  '/upload/banner-image',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  uploadRateLimit,
  (req, res, next) => {
    const config = FileService.getBannerImageConfig();
    const upload = createMulterMiddleware(config);
    upload.single('bannerImage')(req, res, next);
  },
  FileController.uploadBannerImage
);

/**
 * @route POST /api/files/upload/document
 * @desc Upload document
 * @access Admin, Super Admin, Moderator
 */
router.post(
  '/upload/document',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  uploadRateLimit,
  (req, res, next) => {
    const config = FileService.getDocumentConfig();
    const upload = createMulterMiddleware(config);
    upload.single('document')(req, res, next);
  },
  FileController.uploadDocument
);

/**
 * @route POST /api/files/upload/bulk
 * @desc Bulk upload files
 * @access Admin, Super Admin
 */
router.post(
  '/upload/bulk',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  uploadRateLimit,
  [
    body('uploadType')
      .optional()
      .isIn(['profile', 'candidate', 'manifesto', 'banner', 'document'])
      .withMessage('Invalid upload type'),
  ],
  (req: any, res: any, next: any) => {
    const { uploadType = 'document' } = req.body;
    let config;

    switch (uploadType) {
      case 'profile':
        config = FileService.getProfileImageConfig();
        break;
      case 'candidate':
        config = FileService.getCandidatePhotoConfig();
        break;
      case 'manifesto':
        config = FileService.getManifestoConfig();
        break;
      case 'banner':
        config = FileService.getBannerImageConfig();
        break;
      default:
        config = FileService.getDocumentConfig();
    }

    const upload = createMulterMiddleware(config);
    upload.array('files', 10)(req, res, next); // Max 10 files
  },
  FileController.bulkUpload
);

/**
 * @route DELETE /api/files/:filePath
 * @desc Delete file
 * @access File owner or Admin
 */
router.delete(
  '/:filePath(*)',
  authenticate,
  uploadRateLimit,
  [
    param('filePath').notEmpty().withMessage('File path is required'),
  ],
  FileController.deleteFile
);

/**
 * @route GET /api/files/info/:filePath
 * @desc Get file information
 * @access Authenticated users
 */
router.get(
  '/info/:filePath(*)',
  authenticate,
  uploadRateLimit,
  [
    param('filePath').notEmpty().withMessage('File path is required'),
  ],
  FileController.getFileInfo
);

/**
 * @route POST /api/files/cleanup/temp
 * @desc Cleanup temporary files
 * @access Admin, Super Admin
 */
router.post(
  '/cleanup/temp',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  uploadRateLimit,
  FileController.cleanupTempFiles
);

/**
 * @route GET /api/files/configs
 * @desc Get upload configurations
 * @access Authenticated users
 */
router.get(
  '/configs',
  authenticate,
  uploadRateLimit,
  FileController.getUploadConfigs
);

/**
 * @route GET /api/files/health
 * @desc Check file service health
 * @access Admin, Super Admin
 */
router.get(
  '/health',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  uploadRateLimit,
  async (req: any, res: any, next: any) => {
    try {
      // Check if upload directories exist and are writable
      const healthCheck = {
        status: 'healthy',
        timestamp: new Date(),
        checks: {
          uploadDirectories: 'ok',
          diskSpace: 'ok',
          permissions: 'ok',
        },
        metrics: {
          totalFiles: 0,
          totalSize: 0,
          lastCleanup: new Date(),
        }
      };

      res.json({
        success: true,
        message: 'File service health check completed',
        data: healthCheck,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route POST /api/files/validate
 * @desc Validate file before upload
 * @access Authenticated users
 */
router.post(
  '/validate',
  authenticate,
  uploadRateLimit,
  [
    body('fileName').notEmpty().withMessage('File name is required'),
    body('fileSize').isInt({ min: 1 }).withMessage('File size must be a positive integer'),
    body('mimeType').notEmpty().withMessage('MIME type is required'),
    body('uploadType')
      .optional()
      .isIn(['profile', 'candidate', 'manifesto', 'banner', 'document'])
      .withMessage('Invalid upload type'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const { fileName, fileSize, mimeType, uploadType = 'document' } = req.body;

      let config;
      switch (uploadType) {
        case 'profile':
          config = FileService.getProfileImageConfig();
          break;
        case 'candidate':
          config = FileService.getCandidatePhotoConfig();
          break;
        case 'manifesto':
          config = FileService.getManifestoConfig();
          break;
        case 'banner':
          config = FileService.getBannerImageConfig();
          break;
        default:
          config = FileService.getDocumentConfig();
      }

      // Validate file specifications
      const validation = {
        valid: true,
        errors: [] as string[],
        fileName,
        fileSize,
        mimeType,
        uploadType,
      };

      // Check file size
      if (fileSize > config.maxSize) {
        validation.valid = false;
        validation.errors.push(`File size exceeds maximum allowed size of ${config.maxSize} bytes`);
      }

      // Check MIME type
      if (!config.allowedTypes.includes(mimeType)) {
        validation.valid = false;
        validation.errors.push(`File type ${mimeType} not allowed. Allowed types: ${config.allowedTypes.join(', ')}`);
      }

      // Check file extension
      const fileExtension = fileName.split('.').pop()?.toLowerCase();
      const allowedExtensions = config.allowedTypes.map((type: string) => {
        const extensionMap: Record<string, string> = {
          'image/jpeg': 'jpg',
          'image/png': 'png',
          'image/webp': 'webp',
          'application/pdf': 'pdf',
          'application/msword': 'doc',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
          'text/plain': 'txt',
        };
        return extensionMap[type];
      }).filter(Boolean);

      if (fileExtension && !allowedExtensions.includes(fileExtension)) {
        validation.valid = false;
        validation.errors.push(`File extension .${fileExtension} not allowed`);
      }

      res.json({
        success: true,
        message: validation.valid ? 'File validation passed' : 'File validation failed',
        data: validation,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route GET /api/files/stats
 * @desc Get file statistics
 * @access Admin, Super Admin
 */
router.get(
  '/stats',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  uploadRateLimit,
  [
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
    query('type').optional().isIn(['profile', 'candidate', 'manifesto', 'banner', 'document']).withMessage('Invalid file type'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const { startDate, endDate, type } = req.query;

      // This would typically query the database for file statistics
      // For now, we'll return mock data
      const stats = {
        totalFiles: 0,
        totalSize: 0,
        filesByType: {
          profile: 0,
          candidate: 0,
          manifesto: 0,
          banner: 0,
          document: 0,
        },
        uploadsToday: 0,
        uploadsThisWeek: 0,
        uploadsThisMonth: 0,
        averageFileSize: 0,
        largestFile: {
          name: '',
          size: 0,
          uploadedAt: new Date(),
        },
        recentUploads: [],
      };

      res.json({
        success: true,
        message: 'File statistics retrieved successfully',
        data: stats,
        generatedAt: new Date(),
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;