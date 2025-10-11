// backend/src/types/file.types.ts

import { FileCategory, AccessLevel } from '@prisma/client';

// File Upload Types
export interface FileUploadRequest {
  category: FileCategory;
  subCategory?: string;
  tags?: string[];
  isPublic?: boolean;
  accessLevel?: AccessLevel;
  metadata?: Record<string, any>;
  expiresAt?: Date;
}

export interface FileUploadResult {
  id: string;
  originalName: string;
  filename: string;
  path: string;
  url: string;
  size: number;
  mimeType: string;
  thumbnailUrl?: string;
  category: FileCategory;
  uploadedById?: string;
  createdAt: Date;
}

export interface FileUploadOptions {
  destination: string;
  allowedTypes: string[];
  maxSize: number;
  generateThumbnail?: boolean;
  thumbnailSize?: { width: number; height: number };
  compress?: boolean;
  quality?: number;
  watermark?: boolean;
  watermarkText?: string;
}

// File Management Types
export interface FileSearchQuery {
  category?: FileCategory;
  subCategory?: string;
  tags?: string[];
  uploadedById?: string;
  mimeType?: string;
  isPublic?: boolean;
  accessLevel?: AccessLevel;
  createdAfter?: Date;
  createdBefore?: Date;
  sizeMin?: number;
  sizeMax?: number;
  filename?: string;
  originalName?: string;
}

export interface FileSearchResult {
  files: FileInfo[];
  totalCount: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface FileInfo {
  id: string;
  originalName: string;
  filename: string;
  path: string;
  url: string;
  size: number;
  mimeType: string;
  category: FileCategory;
  subCategory?: string;
  tags: string[];
  thumbnailUrl?: string;
  isPublic: boolean;
  accessLevel: AccessLevel;
  downloadCount: number;
  checksum?: string;
  metadata?: Record<string, any>;
  uploadedBy?: {
    id: string;
    firstName: string;
    lastName: string;
    email: string;
  };
  createdAt: Date;
  updatedAt: Date;
  lastAccessed: Date;
  expiresAt?: Date;
}

// File Processing Types
export interface ImageProcessingOptions {
  resize?: {
    width?: number;
    height?: number;
    fit?: 'cover' | 'contain' | 'fill' | 'inside' | 'outside';
    position?: string;
  };
  crop?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp' | 'avif';
  blur?: number;
  sharpen?: boolean;
  grayscale?: boolean;
  normalize?: boolean;
  rotate?: number;
  flip?: boolean;
  flop?: boolean;
  watermark?: {
    text?: string;
    image?: string;
    position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center';
    opacity?: number;
  };
}

export interface DocumentProcessingOptions {
  extractText?: boolean;
  generateThumbnail?: boolean;
  thumbnailPage?: number;
  compress?: boolean;
  watermark?: {
    text?: string;
    position?: string;
    opacity?: number;
  };
}

// File Validation Types
export interface FileValidationRule {
  maxSize: number;
  allowedTypes: string[];
  allowedExtensions?: string[];
  minDimensions?: { width: number; height: number };
  maxDimensions?: { width: number; height: number };
  aspectRatio?: number;
  quality?: { min: number; max: number };
}

export interface FileValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  metadata?: {
    dimensions?: { width: number; height: number };
    duration?: number;
    bitrate?: number;
    frameRate?: number;
    colorSpace?: string;
    hasAlpha?: boolean;
  };
}

// File Storage Types
export interface StorageProvider {
  type: 'local' | 'aws-s3' | 'cloudinary' | 'azure' | 'gcp';
  config: Record<string, any>;
}

export interface StorageResult {
  success: boolean;
  url?: string;
  path?: string;
  key?: string;
  publicId?: string;
  error?: string;
}

// File Sharing Types
export interface FileShareRequest {
  fileId: string;
  shareType: 'public' | 'password' | 'expiring' | 'authenticated';
  password?: string;
  expiresAt?: Date;
  maxDownloads?: number;
  allowedEmails?: string[];
  permissions: ('view' | 'download' | 'share')[];
}

export interface FileShareResponse {
  shareId: string;
  shareUrl: string;
  expiresAt?: Date;
  maxDownloads?: number;
  currentDownloads: number;
  isActive: boolean;
}

export interface FileShareInfo {
  id: string;
  fileId: string;
  shareType: string;
  shareUrl: string;
  password?: string;
  expiresAt?: Date;
  maxDownloads?: number;
  currentDownloads: number;
  allowedEmails: string[];
  permissions: string[];
  isActive: boolean;
  createdBy: string;
  createdAt: Date;
  lastAccessed?: Date;
}

// File Analytics Types
export interface FileAnalytics {
  fileId: string;
  totalDownloads: number;
  uniqueDownloads: number;
  downloadsByDate: Array<{
    date: string;
    downloads: number;
  }>;
  downloadsByLocation: Array<{
    country: string;
    downloads: number;
  }>;
  downloadsByDevice: Array<{
    deviceType: string;
    downloads: number;
  }>;
  averageDownloadTime: number;
  lastDownload?: Date;
  topReferrers: Array<{
    referrer: string;
    downloads: number;
  }>;
}

// File Backup Types
export interface FileBackupInfo {
  fileId: string;
  backupPath: string;
  backupProvider: string;
  backupDate: Date;
  fileSize: number;
  checksum: string;
  isEncrypted: boolean;
  retentionPolicy: string;
  status: 'pending' | 'completed' | 'failed' | 'expired';
}

// File Conversion Types
export interface FileConversionRequest {
  fileId: string;
  targetFormat: string;
  options?: {
    quality?: number;
    dimensions?: { width: number; height: number };
    fps?: number;
    bitrate?: string;
    codec?: string;
  };
}

export interface FileConversionResult {
  success: boolean;
  convertedFileId?: string;
  convertedFileUrl?: string;
  originalSize: number;
  convertedSize: number;
  compressionRatio: number;
  processingTime: number;
  error?: string;
}

// Predefined file configurations
export const FILE_CONFIGS = {
  PROFILE_IMAGE: {
    destination: 'profiles',
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
    maxSize: 5 * 1024 * 1024, // 5MB
    generateThumbnail: true,
    thumbnailSize: { width: 200, height: 200 },
    compress: true,
    quality: 85,
  },
  CANDIDATE_PHOTO: {
    destination: 'candidates',
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
    maxSize: 10 * 1024 * 1024, // 10MB
    generateThumbnail: true,
    thumbnailSize: { width: 300, height: 400 },
    compress: true,
    quality: 90,
  },
  CANDIDATE_BANNER: {
    destination: 'banners',
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
    maxSize: 15 * 1024 * 1024, // 15MB
    generateThumbnail: true,
    thumbnailSize: { width: 800, height: 300 },
    compress: true,
    quality: 85,
  },
  MANIFESTO: {
    destination: 'manifestos',
    allowedTypes: ['application/pdf', 'image/jpeg', 'image/png'],
    maxSize: 20 * 1024 * 1024, // 20MB
    generateThumbnail: true,
    thumbnailSize: { width: 400, height: 600 },
  },
  ELECTION_COVER: {
    destination: 'election-covers',
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
    maxSize: 10 * 1024 * 1024, // 10MB
    generateThumbnail: true,
    thumbnailSize: { width: 600, height: 400 },
    compress: true,
    quality: 85,
  },
  DOCUMENT: {
    destination: 'documents',
    allowedTypes: [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
      'text/csv',
    ],
    maxSize: 50 * 1024 * 1024, // 50MB
  },
} as const;

// File Categories and their allowed MIME types
export const CATEGORY_MIME_TYPES: Record<FileCategory, string[]> = {
  PROFILE_IMAGE: ['image/jpeg', 'image/png', 'image/webp'],
  CANDIDATE_PHOTO: ['image/jpeg', 'image/png', 'image/webp'],
  CANDIDATE_BANNER: ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'],
  MANIFESTO: ['application/pdf', 'image/jpeg', 'image/png'],
  ELECTION_COVER: ['image/jpeg', 'image/png', 'image/webp'],
  DOCUMENT: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
    'text/csv',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ],
  SYSTEM: ['*/*'],
  TEMP: ['*/*'],
};

// File Size Limits by Category (in bytes)
export const CATEGORY_SIZE_LIMITS: Record<FileCategory, number> = {
  PROFILE_IMAGE: 5 * 1024 * 1024, // 5MB
  CANDIDATE_PHOTO: 10 * 1024 * 1024, // 10MB
  CANDIDATE_BANNER: 15 * 1024 * 1024, // 15MB
  MANIFESTO: 20 * 1024 * 1024, // 20MB
  ELECTION_COVER: 10 * 1024 * 1024, // 10MB
  DOCUMENT: 50 * 1024 * 1024, // 50MB
  SYSTEM: 100 * 1024 * 1024, // 100MB
  TEMP: 25 * 1024 * 1024, // 25MB
};

