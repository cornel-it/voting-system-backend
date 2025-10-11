// backend/src/services/file.service.ts

import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { AppError } from '../utils/errors';
import { prisma } from '../config/database';

export interface FileUploadResult {
  id: string;
  originalName: string;
  filename: string;
  path: string;
  url: string;
  size: number;
  mimeType: string;
  thumbnailUrl?: string;
}

export interface FileUploadOptions {
  destination: string;
  allowedTypes: string[];
  maxSize: number;
  generateThumbnail?: boolean;
  thumbnailSize?: { width: number; height: number };
  compress?: boolean;
  quality?: number;
}

export class FileService {
  private static instance: FileService;
  private uploadDir: string;

  private constructor() {
    this.uploadDir = path.join(__dirname, '../../uploads');
    this.ensureUploadDirectories();
  }

  public static getInstance(): FileService {
    if (!FileService.instance) {
      FileService.instance = new FileService();
    }
    return FileService.instance;
  }

  private async ensureUploadDirectories(): Promise<void> {
    const directories = [
      'profiles',
      'candidates',
      'manifestos',
      'banners',
      'documents',
      'thumbnails',
      'temp'
    ];

    for (const dir of directories) {
      const fullPath = path.join(this.uploadDir, dir);
      try {
        await fs.access(fullPath);
      } catch {
        await fs.mkdir(fullPath, { recursive: true });
        logger.info(`📁 Created upload directory: ${dir}`);
      }
    }
  }

  public getMulterConfig(options: FileUploadOptions): multer.Options {
    const storage = multer.diskStorage({
      destination: (req, file, cb) => {
        const destPath = path.join(this.uploadDir, options.destination);
        cb(null, destPath);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = uuidv4();
        const ext = path.extname(file.originalname);
        const filename = `${uniqueSuffix}${ext}`;
        cb(null, filename);
      }
    });

    const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
      if (options.allowedTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new AppError(`Invalid file type. Allowed types: ${options.allowedTypes.join(', ')}`, 400));
      }
    };

    return {
      storage,
      fileFilter,
      limits: {
        fileSize: options.maxSize,
        files: 5 // Maximum 5 files per request
      }
    };
  }

  public async processFile(
    file: Express.Multer.File,
    options: FileUploadOptions,
    userId?: string
  ): Promise<FileUploadResult> {
    try {
      const fileId = uuidv4();
      const relativePath = path.join(options.destination, file.filename);
      const absolutePath = path.join(this.uploadDir, relativePath);

      let processedPath = absolutePath;
      let thumbnailUrl: string | undefined;

      // Process image if needed
      if (file.mimetype.startsWith('image/')) {
        processedPath = await this.processImage(absolutePath, options);

        if (options.generateThumbnail) {
          thumbnailUrl = await this.generateThumbnail(
            processedPath,
            options.thumbnailSize || { width: 200, height: 200 }
          );
        }
      }

      // Get file stats
      const stats = await fs.stat(processedPath);

      const result: FileUploadResult = {
        id: fileId,
        originalName: file.originalname,
        filename: path.basename(processedPath),
        path: path.relative(this.uploadDir, processedPath),
        url: `/uploads/${path.relative(this.uploadDir, processedPath).replace(/\\/g, '/')}`,
        size: stats.size,
        mimeType: file.mimetype,
        thumbnailUrl
      };

      // Store file metadata in database
      if (userId) {
        await this.saveFileMetadata(result, userId);
      }

      logger.info(`📎 File processed: ${file.originalname} -> ${result.filename}`);
      return result;

    } catch (error) {
      logger.error('Error processing file:', error);

      // Cleanup file on error
      try {
        await fs.unlink(file.path);
      } catch (cleanupError) {
        logger.error('Error cleaning up file:', cleanupError);
      }

      throw new AppError('File processing failed', 500);
    }
  }

  private async processImage(
    filePath: string,
    options: FileUploadOptions
  ): Promise<string> {
    try {
      if (!options.compress && !options.quality) {
        return filePath;
      }

      const processedPath = filePath.replace(/(\.[^.]+)$/, '_processed$1');

      let pipeline = sharp(filePath);

      // Auto-rotate based on EXIF
      pipeline = pipeline.rotate();

      // Apply compression if specified
      if (options.compress || options.quality) {
        const ext = path.extname(filePath).toLowerCase();

        switch (ext) {
          case '.jpg':
          case '.jpeg':
            pipeline = pipeline.jpeg({
              quality: options.quality || 85,
              progressive: true
            });
            break;
          case '.png':
            pipeline = pipeline.png({
              quality: options.quality || 85,
              compressionLevel: 6
            });
            break;
          case '.webp':
            pipeline = pipeline.webp({
              quality: options.quality || 85
            });
            break;
        }
      }

      await pipeline.toFile(processedPath);

      // Remove original file
      await fs.unlink(filePath);

      return processedPath;

    } catch (error) {
      logger.error('Error processing image:', error);
      return filePath; // Return original if processing fails
    }
  }

  private async generateThumbnail(
    filePath: string,
    size: { width: number; height: number }
  ): Promise<string> {
    try {
      const ext = path.extname(filePath);
      const thumbnailPath = path.join(
        this.uploadDir,
        'thumbnails',
        `${path.basename(filePath, ext)}_thumb${ext}`
      );

      await sharp(filePath)
        .resize(size.width, size.height, {
          fit: 'cover',
          position: 'center'
        })
        .jpeg({ quality: 80 })
        .toFile(thumbnailPath);

      const relativePath = path.relative(this.uploadDir, thumbnailPath);
      return `/uploads/${relativePath.replace(/\\/g, '/')}`;

    } catch (error) {
      logger.error('Error generating thumbnail:', error);
      throw error;
    }
  }

  private async saveFileMetadata(file: FileUploadResult, userId: string): Promise<void> {
    try {
      const category = this.getCategoryFromPath(file.path);

      await prisma.file.create({
        data: {
          id: file.id,
          originalName: file.originalName,
          filename: file.filename,
          path: file.path,
          url: file.url,
          size: file.size,
          mimeType: file.mimeType,
          category,
          thumbnailUrl: file.thumbnailUrl,
          uploadedById: userId,
          isPublic: category === 'ELECTION_COVER' || category === 'CANDIDATE_PHOTO',
          accessLevel: 'PUBLIC',
        }
      });

      // Also log the upload for audit trail
      await prisma.auditLog.create({
        data: {
          action: 'FILE_UPLOADED',
          category: 'SYSTEM',
          severity: 'LOW',
          userId,
          metadata: {
            fileId: file.id,
            filename: file.filename,
            originalName: file.originalName,
            size: file.size,
            mimeType: file.mimeType,
            path: file.path
          }
        }
      });
    } catch (error) {
      logger.error('Error saving file metadata:', error);
    }
  }

  private getCategoryFromPath(filePath: string): 'PROFILE_IMAGE' | 'CANDIDATE_PHOTO' | 'CANDIDATE_BANNER' | 'MANIFESTO' | 'ELECTION_COVER' | 'DOCUMENT' | 'SYSTEM' | 'TEMP' {
    if (filePath.includes('profiles')) return 'PROFILE_IMAGE';
    if (filePath.includes('candidates')) return 'CANDIDATE_PHOTO';
    if (filePath.includes('banners')) return 'CANDIDATE_BANNER';
    if (filePath.includes('manifestos')) return 'MANIFESTO';
    if (filePath.includes('documents')) return 'DOCUMENT';
    if (filePath.includes('temp')) return 'TEMP';
    return 'SYSTEM';
  }

  public async deleteFile(filePath: string, userId?: string): Promise<void> {
    try {
      // First check if file exists in database
      const fileRecord = await prisma.file.findFirst({
        where: { path: filePath }
      });

      if (!fileRecord) {
        throw new AppError('File not found in database', 404);
      }

      const absolutePath = path.join(this.uploadDir, filePath);

      // Check if physical file exists
      try {
        await fs.access(absolutePath);
      } catch {
        throw new AppError('Physical file not found', 404);
      }

      // Delete main file
      await fs.unlink(absolutePath);

      // Delete thumbnail if it exists
      if (fileRecord.thumbnailUrl) {
        const thumbnailPath = path.join(this.uploadDir, fileRecord.thumbnailUrl.replace('/uploads/', ''));
        try {
          await fs.unlink(thumbnailPath);
        } catch {
          // Thumbnail might not exist, ignore error
        }
      }

      // Delete from database
      await prisma.file.delete({
        where: { id: fileRecord.id }
      });

      // Log deletion
      if (userId) {
        await prisma.auditLog.create({
          data: {
            action: 'FILE_DELETED',
            category: 'SYSTEM',
            severity: 'LOW',
            userId,
            metadata: {
              fileId: fileRecord.id,
              filePath,
              originalName: fileRecord.originalName,
              deletedAt: new Date().toISOString()
            }
          }
        });
      }

      logger.info(`🗑️  File deleted: ${filePath}`);

    } catch (error) {
      logger.error('Error deleting file:', error);
      throw error;
    }
  }

  public async getFileById(fileId: string): Promise<any> {
    try {
      const file = await prisma.file.findUnique({
        where: { id: fileId },
        include: {
          uploadedBy: {
            select: {
              firstName: true,
              lastName: true,
            }
          }
        }
      });

      if (!file) {
        throw new AppError('File not found', 404);
      }

      // Update access count and last accessed
      await prisma.file.update({
        where: { id: fileId },
        data: {
          downloadCount: { increment: 1 },
          lastAccessed: new Date()
        }
      });

      return {
        id: file.id,
        originalName: file.originalName,
        filename: file.filename,
        path: file.path,
        url: file.url,
        size: file.size,
        mimeType: file.mimeType,
        category: file.category,
        thumbnailUrl: file.thumbnailUrl,
        isPublic: file.isPublic,
        uploadedBy: file.uploadedBy ? `${file.uploadedBy.firstName} ${file.uploadedBy.lastName}` : null,
        uploadedAt: file.createdAt,
        downloadCount: file.downloadCount + 1,
        lastAccessed: new Date()
      };
    } catch (error) {
      logger.error('Error getting file by ID:', error);
      throw error;
    }
  }

  public async getUserFiles(userId: string, category?: string): Promise<any[]> {
    try {
      const where: any = { uploadedById: userId };
      if (category) {
        where.category = category;
      }

      const files = await prisma.file.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          originalName: true,
          filename: true,
          url: true,
          size: true,
          mimeType: true,
          category: true,
          thumbnailUrl: true,
          downloadCount: true,
          createdAt: true,
          lastAccessed: true
        }
      });

      return files;
    } catch (error) {
      logger.error('Error getting user files:', error);
      throw error;
    }
  }

  public async getPublicFiles(category?: string, limit?: number): Promise<any[]> {
    try {
      const where: any = { isPublic: true };
      if (category) {
        where.category = category;
      }

      const files = await prisma.file.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: {
          id: true,
          originalName: true,
          filename: true,
          url: true,
          size: true,
          mimeType: true,
          category: true,
          thumbnailUrl: true,
          downloadCount: true,
          createdAt: true
        }
      });

      return files;
    } catch (error) {
      logger.error('Error getting public files:', error);
      throw error;
    }
  }

  public async getFileStatistics(): Promise<any> {
    try {
      const [
        totalFiles,
        totalSize,
        filesByCategory,
        filesByType,
        recentUploads
      ] = await Promise.all([
        prisma.file.count(),
        prisma.file.aggregate({
          _sum: { size: true }
        }),
        prisma.file.groupBy({
          by: ['category'],
          _count: true,
          _sum: { size: true }
        }),
        prisma.file.groupBy({
          by: ['mimeType'],
          _count: true,
          _sum: { size: true }
        }),
        prisma.file.count({
          where: {
            createdAt: {
              gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
            }
          }
        })
      ]);

      return {
        totalFiles,
        totalSize: totalSize._sum.size || 0,
        averageFileSize: totalFiles > 0 ? (totalSize._sum.size || 0) / totalFiles : 0,
        filesByCategory: filesByCategory.map(item => ({
          category: item.category,
          count: item._count,
          totalSize: item._sum.size || 0
        })),
        filesByType: filesByType.map(item => ({
          mimeType: item.mimeType,
          count: item._count,
          totalSize: item._sum.size || 0
        })),
        recentUploads
      };
    } catch (error) {
      logger.error('Error getting file statistics:', error);
      throw error;
    }
  }

  public async cleanupTempFiles(): Promise<void> {
    try {
      const tempDir = path.join(this.uploadDir, 'temp');
      const files = await fs.readdir(tempDir);
      const oneHourAgo = Date.now() - (60 * 60 * 1000);

      let cleaned = 0;
      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);

        if (stats.mtime.getTime() < oneHourAgo) {
          await fs.unlink(filePath);
          cleaned++;
        }
      }

      if (cleaned > 0) {
        logger.info(`🧹 Cleaned up ${cleaned} temporary files`);
      }

    } catch (error) {
      logger.error('Error cleaning up temp files:', error);
    }
  }

  public async getFileInfo(filePath: string): Promise<any> {
    try {
      const absolutePath = path.join(this.uploadDir, filePath);
      const stats = await fs.stat(absolutePath);

      return {
        path: filePath,
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        exists: true
      };
    } catch (error) {
      return {
        path: filePath,
        exists: false
      };
    }
  }

  public async validateFile(file: Express.Multer.File, options: FileUploadOptions): Promise<void> {
    // Check file size
    if (file.size > options.maxSize) {
      throw new AppError(`File too large. Maximum size: ${this.formatFileSize(options.maxSize)}`, 400);
    }

    // Check file type
    if (!options.allowedTypes.includes(file.mimetype)) {
      throw new AppError(`Invalid file type. Allowed types: ${options.allowedTypes.join(', ')}`, 400);
    }

    // Additional security checks for images
    if (file.mimetype.startsWith('image/')) {
      try {
        const metadata = await sharp(file.path).metadata();

        // Check image dimensions (prevent extremely large images)
        if (metadata.width && metadata.height) {
          if (metadata.width > 5000 || metadata.height > 5000) {
            throw new AppError('Image dimensions too large (max 5000x5000)', 400);
          }
        }
      } catch (error) {
        throw new AppError('Invalid image file', 400);
      }
    }
  }

  private formatFileSize(bytes: number): string {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${Math.round(bytes / Math.pow(1024, i) * 100) / 100} ${sizes[i]}`;
  }

  // Predefined configurations for different file types

  public static getProfileImageConfig(): FileUploadOptions {
    return {
      destination: 'profiles',
      allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
      maxSize: 5 * 1024 * 1024, // 5MB
      generateThumbnail: true,
      thumbnailSize: { width: 200, height: 200 },
      compress: true,
      quality: 85
    };
  }

  public static getCandidatePhotoConfig(): FileUploadOptions {
    return {
      destination: 'candidates',
      allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
      maxSize: 10 * 1024 * 1024, // 10MB
      generateThumbnail: true,
      thumbnailSize: { width: 300, height: 400 },
      compress: true,
      quality: 90
    };
  }

  public static getManifestoConfig(): FileUploadOptions {
    return {
      destination: 'manifestos',
      allowedTypes: ['application/pdf', 'image/jpeg', 'image/png'],
      maxSize: 20 * 1024 * 1024, // 20MB
      generateThumbnail: false
    };
  }

  public static getBannerImageConfig(): FileUploadOptions {
    return {
      destination: 'banners',
      allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
      maxSize: 15 * 1024 * 1024, // 15MB
      generateThumbnail: true,
      thumbnailSize: { width: 800, height: 300 },
      compress: true,
      quality: 85
    };
  }

  public static getDocumentConfig(): FileUploadOptions {
    return {
      destination: 'documents',
      allowedTypes: [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain'
      ],
      maxSize: 50 * 1024 * 1024, // 50MB
      generateThumbnail: false
    };
  }
}

// Export singleton instance
export const fileService = FileService.getInstance();

export default fileService;