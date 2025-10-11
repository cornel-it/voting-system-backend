// backend/src/middleware/upload.middleware.ts

import multer from 'multer';
import path from 'path';
import { Request } from 'express';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import { AppError } from '../utils/errors';
import fs from 'fs/promises';

// File type definitions
export interface FileFilter {
  mimeTypes: string[];
  extensions: string[];
  maxSize: number;
  description: string;
}

// Predefined file filters
export const fileFilters: Record<string, FileFilter> = {
  image: {
    mimeTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'],
    extensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
    maxSize: 5 * 1024 * 1024, // 5MB
    description: 'Images (JPEG, PNG, GIF, WebP)'
  },
  avatar: {
    mimeTypes: ['image/jpeg', 'image/jpg', 'image/png'],
    extensions: ['.jpg', '.jpeg', '.png'],
    maxSize: 2 * 1024 * 1024, // 2MB
    description: 'Avatar images (JPEG, PNG)'
  },
  document: {
    mimeTypes: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    extensions: ['.pdf', '.doc', '.docx'],
    maxSize: 10 * 1024 * 1024, // 10MB
    description: 'Documents (PDF, DOC, DOCX)'
  },
  spreadsheet: {
    mimeTypes: ['text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    extensions: ['.csv', '.xls', '.xlsx'],
    maxSize: 5 * 1024 * 1024, // 5MB
    description: 'Spreadsheets (CSV, XLS, XLSX)'
  },
  candidatePhoto: {
    mimeTypes: ['image/jpeg', 'image/jpg', 'image/png'],
    extensions: ['.jpg', '.jpeg', '.png'],
    maxSize: 3 * 1024 * 1024, // 3MB
    description: 'Candidate photos (JPEG, PNG)'
  }
};

// Storage configuration
const createStorage = (destination: string, useOriginalName: boolean = false) => {
  return multer.diskStorage({
    destination: async (req, file, cb) => {
      try {
        const uploadPath = path.join(process.cwd(), 'uploads', destination);
        await fs.mkdir(uploadPath, { recursive: true });
        cb(null, uploadPath);
      } catch (error) {
        cb(error as Error, '');
      }
    },
    filename: (req, file, cb) => {
      if (useOriginalName) {
        const timestamp = Date.now();
        const cleanName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${timestamp}_${cleanName}`);
      } else {
        const uniqueSuffix = `${Date.now()}_${uuidv4()}`;
        const extension = path.extname(file.originalname);
        cb(null, `${uniqueSuffix}${extension}`);
      }
    }
  });
};

// Memory storage for processing
const memoryStorage = multer.memoryStorage();

// File filter creator
const createFileFilter = (filter: FileFilter) => {
  return (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    // Check MIME type
    if (!filter.mimeTypes.includes(file.mimetype)) {
      return cb(new AppError(`Invalid file type. Allowed: ${filter.description}`, 400));
    }

    // Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (!filter.extensions.includes(ext)) {
      return cb(new AppError(`Invalid file extension. Allowed: ${filter.extensions.join(', ')}`, 400));
    }

    // Check file name
    if (file.originalname.length > 255) {
      return cb(new AppError('File name too long', 400));
    }

    // Check for null bytes (security)
    if (file.originalname.includes('\0')) {
      return cb(new AppError('Invalid file name', 400));
    }

    cb(null, true);
  };
};

// Avatar upload middleware
export const avatarUpload = multer({
  storage: memoryStorage,
  fileFilter: createFileFilter(fileFilters.avatar),
  limits: {
    fileSize: fileFilters.avatar.maxSize,
    files: 1
  }
});

// Candidate photo upload middleware
export const candidatePhotoUpload = multer({
  storage: memoryStorage,
  fileFilter: createFileFilter(fileFilters.candidatePhoto),
  limits: {
    fileSize: fileFilters.candidatePhoto.maxSize,
    files: 1
  }
});

// Document upload middleware
export const documentUpload = multer({
  storage: createStorage('documents'),
  fileFilter: createFileFilter(fileFilters.document),
  limits: {
    fileSize: fileFilters.document.maxSize,
    files: 5
  }
});

// Bulk voter import upload
export const voterImportUpload = multer({
  storage: memoryStorage,
  fileFilter: createFileFilter(fileFilters.spreadsheet),
  limits: {
    fileSize: fileFilters.spreadsheet.maxSize,
    files: 1
  }
});

// General file upload
export const generalFileUpload = (filterType: keyof typeof fileFilters, destination: string = 'general') => {
  const filter = fileFilters[filterType];
  return multer({
    storage: createStorage(destination),
    fileFilter: createFileFilter(filter),
    limits: {
      fileSize: filter.maxSize,
      files: 10
    }
  });
};

// Image processing middleware
export const processImage = (options: {
  width?: number;
  height?: number;
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
  destination?: string;
} = {}) => {
  return async (req: any, res: any, next: any) => {
    try {
      if (!req.file || !req.file.buffer) {
        return next();
      }

      const {
        width = 800,
        height = 600,
        quality = 80,
        format = 'jpeg',
        destination = 'images'
      } = options;

      // Create unique filename
      const uniqueSuffix = `${Date.now()}_${uuidv4()}`;
      const fileName = `${uniqueSuffix}.${format}`;
      const uploadPath = path.join(process.cwd(), 'uploads', destination);
      const filePath = path.join(uploadPath, fileName);

      // Ensure directory exists
      await fs.mkdir(uploadPath, { recursive: true });

      // Process image
      let sharpInstance = sharp(req.file.buffer);

      // Resize if dimensions specified
      if (width || height) {
        sharpInstance = sharpInstance.resize(width, height, {
          fit: 'inside',
          withoutEnlargement: true
        });
      }

      // Set format and quality
      if (format === 'jpeg') {
        sharpInstance = sharpInstance.jpeg({ quality });
      } else if (format === 'png') {
        sharpInstance = sharpInstance.png({ quality });
      } else if (format === 'webp') {
        sharpInstance = sharpInstance.webp({ quality });
      }

      // Save processed image
      await sharpInstance.toFile(filePath);

      // Update file info
      req.file.filename = fileName;
      req.file.path = filePath;
      req.file.destination = uploadPath;

      // Get file stats
      const stats = await fs.stat(filePath);
      req.file.size = stats.size;

      next();
    } catch (error) {
      next(new AppError('Image processing failed', 500));
    }
  };
};

// Avatar processing middleware
export const processAvatar = processImage({
  width: 200,
  height: 200,
  quality: 85,
  format: 'jpeg',
  destination: 'avatars'
});

// Candidate photo processing middleware
export const processCandidatePhoto = processImage({
  width: 400,
  height: 500,
  quality: 90,
  format: 'jpeg',
  destination: 'candidates'
});

// File validation middleware
export const validateFile = (req: any, res: any, next: any) => {
  if (!req.file) {
    return next(new AppError('No file uploaded', 400));
  }

  // Additional validation for specific file types
  if (req.file.mimetype.startsWith('image/')) {
    // Validate image dimensions
    sharp(req.file.buffer)
      .metadata()
      .then(metadata => {
        if (!metadata.width || !metadata.height) {
          return next(new AppError('Invalid image file', 400));
        }

        // Check minimum dimensions
        if (metadata.width < 50 || metadata.height < 50) {
          return next(new AppError('Image too small (minimum 50x50 pixels)', 400));
        }

        // Check maximum dimensions
        if (metadata.width > 4000 || metadata.height > 4000) {
          return next(new AppError('Image too large (maximum 4000x4000 pixels)', 400));
        }

        next();
      })
      .catch(error => {
        next(new AppError('Invalid image file', 400));
      });
  } else {
    next();
  }
};

// File cleanup middleware (removes uploaded files on error)
export const fileCleanup = (req: any, res: any, next: any) => {
  const originalNext = next;

  next = async (error?: any) => {
    if (error && req.file?.path) {
      try {
        await fs.unlink(req.file.path);
      } catch (cleanupError) {
        console.error('File cleanup failed:', cleanupError);
      }
    }

    if (error && req.files) {
      // Handle multiple files
      const files = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
      for (const file of files) {
        if (file.path) {
          try {
            await fs.unlink(file.path);
          } catch (cleanupError) {
            console.error('File cleanup failed:', cleanupError);
          }
        }
      }
    }

    originalNext(error);
  };

  next();
};

// Virus scanning middleware (placeholder for integration with antivirus)
export const virusScan = async (req: any, res: any, next: any) => {
  try {
    if (!req.file?.buffer && !req.file?.path) {
      return next();
    }

    // Placeholder for virus scanning integration
    // In production, integrate with ClamAV or similar

    // Basic file signature validation
    const buffer = req.file.buffer || await fs.readFile(req.file.path);
    const fileSignature = buffer.toString('hex', 0, 8);

    // Check for common malicious signatures (basic implementation)
    const maliciousSignatures = [
      '4d5a9000', // PE executable
      '7f454c46', // ELF executable
      '504b0304'  // ZIP with potential executable
    ];

    if (req.file.mimetype.startsWith('image/') || req.file.mimetype.startsWith('application/pdf')) {
      // Allow known safe types after signature check
      const imageSignatures = {
        'ffd8ffe0': 'jpeg',
        'ffd8ffe1': 'jpeg',
        'ffd8ffe2': 'jpeg',
        '89504e47': 'png',
        '47494638': 'gif',
        '52494646': 'webp',
        '25504446': 'pdf'
      };

      const isValidSignature = Object.keys(imageSignatures).some(sig =>
        fileSignature.startsWith(sig)
      );

      if (!isValidSignature) {
        return next(new AppError('Invalid file format', 400));
      }
    }

    // Check for malicious signatures
    const isMalicious = maliciousSignatures.some(sig =>
      fileSignature.startsWith(sig)
    );

    if (isMalicious) {
      return next(new AppError('File contains potentially harmful content', 400));
    }

    next();
  } catch (error) {
    next(new AppError('File validation failed', 500));
  }
};

// File size validation middleware
export const validateFileSize = (maxSize: number) => {
  return (req: any, res: any, next: any) => {
    if (req.file && req.file.size > maxSize) {
      return next(new AppError(`File too large. Maximum size is ${Math.round(maxSize / 1024 / 1024)}MB`, 400));
    }

    if (req.files) {
      const files = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
      for (const file of files) {
        if (file.size > maxSize) {
          return next(new AppError(`File too large. Maximum size is ${Math.round(maxSize / 1024 / 1024)}MB`, 400));
        }
      }
    }

    next();
  };
};

export default {
  avatarUpload,
  candidatePhotoUpload,
  documentUpload,
  voterImportUpload,
  generalFileUpload,
  processImage,
  processAvatar,
  processCandidatePhoto,
  validateFile,
  fileCleanup,
  virusScan,
  validateFileSize,
  fileFilters
};