import { Request, Response, NextFunction } from 'express';
import { fileService, FileService } from '../services/file.service';
import { auditService } from '../services/audit.service';
import { AppError } from '../utils/errors';
import { UserRole } from '@prisma/client';
import { validationResult } from 'express-validator';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
  ipAddress?: string;
  userAgent?: string;
}

export class FileController {
  /**
   * Upload profile image
   */
  public static async uploadProfileImage(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.file) {
        throw new AppError('No file uploaded', 400);
      }

      const userId = req.user!.id;
      const config = FileService.getProfileImageConfig();

      // Validate file
      await fileService.validateFile(req.file, config);

      // Process file
      const result = await fileService.processFile(req.file, config, userId);

      // Log file upload
      await auditService.logAction({
        action: 'PROFILE_IMAGE_UPLOADED',
        category: 'USER',
        severity: 'LOW',
        userId,
        metadata: {
          filename: result.filename,
          size: result.size,
          originalName: result.originalName,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Profile image uploaded successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload candidate photo
   */
  public static async uploadCandidatePhoto(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.file) {
        throw new AppError('No file uploaded', 400);
      }

      const userId = req.user!.id;
      const config = FileService.getCandidatePhotoConfig();

      // Validate file
      await fileService.validateFile(req.file, config);

      // Process file
      const result = await fileService.processFile(req.file, config, userId);

      // Log file upload
      await auditService.logAction({
        action: 'CANDIDATE_PHOTO_UPLOADED',
        category: 'CANDIDATE',
        severity: 'LOW',
        userId,
        metadata: {
          filename: result.filename,
          size: result.size,
          originalName: result.originalName,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Candidate photo uploaded successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload manifesto document
   */
  public static async uploadManifesto(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.file) {
        throw new AppError('No file uploaded', 400);
      }

      const userId = req.user!.id;
      const config = FileService.getManifestoConfig();

      // Validate file
      await fileService.validateFile(req.file, config);

      // Process file
      const result = await fileService.processFile(req.file, config, userId);

      // Log file upload
      await auditService.logAction({
        action: 'MANIFESTO_UPLOADED',
        category: 'CANDIDATE',
        severity: 'LOW',
        userId,
        metadata: {
          filename: result.filename,
          size: result.size,
          originalName: result.originalName,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Manifesto uploaded successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload banner image
   */
  public static async uploadBannerImage(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.file) {
        throw new AppError('No file uploaded', 400);
      }

      const userRole = req.user!.role;
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to upload banner images', 403);
      }

      const userId = req.user!.id;
      const config = FileService.getBannerImageConfig();

      // Validate file
      await fileService.validateFile(req.file, config);

      // Process file
      const result = await fileService.processFile(req.file, config, userId);

      // Log file upload
      await auditService.logAction({
        action: 'BANNER_IMAGE_UPLOADED',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId,
        metadata: {
          filename: result.filename,
          size: result.size,
          originalName: result.originalName,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Banner image uploaded successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload document
   */
  public static async uploadDocument(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.file) {
        throw new AppError('No file uploaded', 400);
      }

      const userRole = req.user!.role;
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to upload documents', 403);
      }

      const userId = req.user!.id;
      const config = FileService.getDocumentConfig();

      // Validate file
      await fileService.validateFile(req.file, config);

      // Process file
      const result = await fileService.processFile(req.file, config, userId);

      // Log file upload
      await auditService.logAction({
        action: 'DOCUMENT_UPLOADED',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId,
        metadata: {
          filename: result.filename,
          size: result.size,
          originalName: result.originalName,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Document uploaded successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete file
   */
  public static async deleteFile(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const { filePath } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      if (!filePath) {
        throw new AppError('File path is required', 400);
      }

      // Check permissions - users can delete their own files, admins can delete any
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        // Additional validation would be needed here to check if file belongs to user
        // For now, we'll allow the service to handle the validation
      }

      await fileService.deleteFile(filePath, userId);

      // Log file deletion
      await auditService.logAction({
        action: 'FILE_DELETED',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId,
        metadata: {
          filePath,
          deletedBy: userRole,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'File deleted successfully',
        data: {
          filePath,
          deletedAt: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get file information
   */
  public static async getFileInfo(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const { filePath } = req.params;

      if (!filePath) {
        throw new AppError('File path is required', 400);
      }

      const fileInfo = await fileService.getFileInfo(filePath);

      res.json({
        success: true,
        message: 'File information retrieved successfully',
        data: fileInfo,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Cleanup temporary files (Admin only)
   */
  public static async cleanupTempFiles(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to cleanup temporary files', 403);
      }

      await fileService.cleanupTempFiles();

      // Log cleanup action
      await auditService.logAction({
        action: 'TEMP_FILES_CLEANUP',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          triggeredBy: userRole,
          cleanupTime: new Date(),
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Temporary files cleanup completed',
        data: {
          cleanupTime: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get upload configurations
   */
  public static async getUploadConfigs(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const configs = {
        profileImage: FileService.getProfileImageConfig(),
        candidatePhoto: FileService.getCandidatePhotoConfig(),
        manifesto: FileService.getManifestoConfig(),
        bannerImage: FileService.getBannerImageConfig(),
        document: FileService.getDocumentConfig(),
      };

      // Remove sensitive information
      const sanitizedConfigs = Object.entries(configs).reduce((acc, [key, config]) => {
        acc[key] = {
          destination: config.destination,
          allowedTypes: config.allowedTypes,
          maxSize: config.maxSize,
          generateThumbnail: config.generateThumbnail,
          thumbnailSize: config.thumbnailSize,
        };
        return acc;
      }, {} as any);

      res.json({
        success: true,
        message: 'Upload configurations retrieved successfully',
        data: sanitizedConfigs,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Bulk upload files
   */
  public static async bulkUpload(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      if (!req.files || !Array.isArray(req.files) || req.files.length === 0) {
        throw new AppError('No files uploaded', 400);
      }

      const userRole = req.user!.role;
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions for bulk upload', 403);
      }

      const userId = req.user!.id;
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

      const results = [];
      const uploadErrors = [];

      for (const file of req.files as Express.Multer.File[]) {
        try {
          await fileService.validateFile(file, config);
          const result = await fileService.processFile(file, config, userId);
          results.push(result);
        } catch (error) {
          uploadErrors.push({
            filename: file.originalname,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      }

      // Log bulk upload
      await auditService.logAction({
        action: 'BULK_FILES_UPLOADED',
        category: 'SYSTEM',
        severity: 'MEDIUM',
        userId,
        metadata: {
          uploadType,
          totalFiles: req.files.length,
          successfulUploads: results.length,
          failedUploads: uploadErrors.length,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: `Bulk upload completed. ${results.length} files uploaded successfully, ${uploadErrors.length} failed.`,
        data: {
          successful: results,
          failed: uploadErrors,
          summary: {
            total: req.files.length,
            successful: results.length,
            failed: uploadErrors.length,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }
}

export default FileController;