-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('SUPER_ADMIN', 'ADMIN', 'MODERATOR', 'VOTER');

-- CreateEnum
CREATE TYPE "ElectionType" AS ENUM ('PRESIDENTIAL', 'DEPARTMENTAL', 'FACULTY', 'CLUB', 'SOCIETY', 'REFERENDUM', 'POLL');

-- CreateEnum
CREATE TYPE "ElectionStatus" AS ENUM ('DRAFT', 'SCHEDULED', 'ACTIVE', 'PAUSED', 'COMPLETED', 'CANCELLED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "CandidateStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'DISQUALIFIED', 'WITHDRAWN');

-- CreateEnum
CREATE TYPE "SessionStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'EXPIRED', 'TERMINATED');

-- CreateEnum
CREATE TYPE "AuditCategory" AS ENUM ('AUTH', 'ELECTION', 'VOTING', 'CANDIDATE', 'USER', 'SYSTEM', 'SECURITY');

-- CreateEnum
CREATE TYPE "AuditSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('ELECTION_STARTED', 'ELECTION_ENDING', 'ELECTION_ENDED', 'VOTE_CONFIRMED', 'RESULT_PUBLISHED', 'ACCOUNT_ACTIVITY', 'SECURITY_ALERT', 'SYSTEM_UPDATE');

-- CreateEnum
CREATE TYPE "NotificationPriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT');

-- CreateEnum
CREATE TYPE "TokenType" AS ENUM ('EMAIL_VERIFICATION', 'PASSWORD_RESET', 'TWO_FACTOR');

-- CreateEnum
CREATE TYPE "FileCategory" AS ENUM ('PROFILE_IMAGE', 'CANDIDATE_PHOTO', 'CANDIDATE_BANNER', 'MANIFESTO', 'ELECTION_COVER', 'DOCUMENT', 'SYSTEM', 'TEMP');

-- CreateEnum
CREATE TYPE "AccessLevel" AS ENUM ('PUBLIC', 'AUTHENTICATED', 'ADMIN_ONLY', 'PRIVATE');

-- CreateEnum
CREATE TYPE "AnalyticsEventType" AS ENUM ('PAGE_VIEW', 'LOGIN', 'LOGOUT', 'VOTE_CAST', 'ELECTION_VIEW', 'CANDIDATE_VIEW', 'RESULT_VIEW', 'DOWNLOAD', 'ERROR', 'SEARCH', 'FILTER', 'SORT');

-- CreateEnum
CREATE TYPE "BackupType" AS ENUM ('FULL', 'INCREMENTAL', 'DIFFERENTIAL', 'MANUAL', 'SCHEDULED');

-- CreateEnum
CREATE TYPE "BackupStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED', 'RESTORED');

-- CreateEnum
CREATE TYPE "AchievementType" AS ENUM ('VOTING_PARTICIPATION', 'ELECTION_CREATOR', 'CANDIDATE_REGISTRATION', 'EARLY_VOTER', 'CONSISTENT_VOTER', 'ELECTION_MODERATOR', 'COMMUNITY_ENGAGEMENT', 'SYSTEM_CONTRIBUTION');

-- CreateEnum
CREATE TYPE "SocialPlatform" AS ENUM ('TWITTER', 'FACEBOOK', 'INSTAGRAM', 'LINKEDIN', 'GITHUB', 'WEBSITE', 'YOUTUBE', 'TIKTOK');

-- CreateEnum
CREATE TYPE "ProfileVisibility" AS ENUM ('PUBLIC', 'AUTHENTICATED_ONLY', 'PRIVATE');

-- CreateEnum
CREATE TYPE "Theme" AS ENUM ('LIGHT', 'DARK', 'AUTO');

-- CreateEnum
CREATE TYPE "IssueCategory" AS ENUM ('BUG', 'FEATURE_REQUEST', 'UI_UX', 'PERFORMANCE', 'SECURITY', 'AUTHENTICATION', 'VOTING_ISSUE', 'ELECTION_SETUP', 'CANDIDATE_REGISTRATION', 'RESULTS_DISPLAY', 'NOTIFICATION', 'FILE_UPLOAD', 'OTHER');

-- CreateEnum
CREATE TYPE "IssuePriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'URGENT');

-- CreateEnum
CREATE TYPE "IssueStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'DUPLICATE', 'WONT_FIX');

-- CreateEnum
CREATE TYPE "CampaignStatus" AS ENUM ('DRAFT', 'SUBMITTED', 'PUBLISHED', 'PAUSED', 'ENDED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "TaskType" AS ENUM ('ELECTION_SETUP', 'CANDIDATE_REVIEW', 'CAMPAIGN_APPROVAL', 'RESULT_VERIFICATION', 'SYSTEM_MAINTENANCE', 'CONTENT_MODERATION', 'USER_SUPPORT', 'DOCUMENTATION', 'TESTING', 'DEPLOYMENT', 'OTHER');

-- CreateEnum
CREATE TYPE "TaskPriority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT', 'CRITICAL');

-- CreateEnum
CREATE TYPE "TaskStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED', 'CANCELLED', 'OVERDUE');

-- CreateEnum
CREATE TYPE "SecurityEventType" AS ENUM ('LOGIN_ATTEMPT', 'FAILED_LOGIN', 'BRUTE_FORCE', 'SUSPICIOUS_ACTIVITY', 'UNAUTHORIZED_ACCESS', 'DATA_BREACH_ATTEMPT', 'SQL_INJECTION', 'XSS_ATTEMPT', 'CSRF_ATTEMPT', 'RATE_LIMIT_EXCEEDED', 'INVALID_TOKEN', 'SESSION_HIJACKING', 'DEVICE_FINGERPRINT_MISMATCH', 'GEOLOCATION_ANOMALY', 'TIME_BASED_ANOMALY', 'VOTING_FRAUD_ATTEMPT', 'SYSTEM_INTRUSION');

-- CreateEnum
CREATE TYPE "CryptoKeyType" AS ENUM ('VOTE_ENCRYPTION', 'SESSION_SIGNING', 'JWT_SIGNING', 'FILE_ENCRYPTION', 'DATABASE_ENCRYPTION', 'BACKUP_ENCRYPTION', 'COMMUNICATION_ENCRYPTION');

-- CreateEnum
CREATE TYPE "ConnectionStatus" AS ENUM ('CONNECTED', 'DISCONNECTED', 'RECONNECTING', 'TIMEOUT');

-- CreateEnum
CREATE TYPE "WidgetType" AS ENUM ('STATS_OVERVIEW', 'RECENT_ELECTIONS', 'VOTING_PROGRESS', 'NOTIFICATIONS', 'QUICK_ACTIONS', 'ANALYTICS_CHART', 'ACTIVITY_FEED', 'SYSTEM_HEALTH', 'USER_ACTIVITY', 'ELECTION_COUNTDOWN');

-- CreateEnum
CREATE TYPE "ReportType" AS ENUM ('ELECTION_SUMMARY', 'VOTING_ANALYTICS', 'USER_ACTIVITY', 'SYSTEM_PERFORMANCE', 'AUDIT_TRAIL', 'CANDIDATE_PERFORMANCE', 'TURNOUT_ANALYSIS', 'COMPARATIVE_ANALYSIS', 'SECURITY_REPORT', 'COMPLIANCE_REPORT');

-- CreateEnum
CREATE TYPE "ReportFormat" AS ENUM ('PDF', 'EXCEL', 'CSV', 'JSON', 'HTML');

-- CreateEnum
CREATE TYPE "ReportStatus" AS ENUM ('GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "FileProcessingStatus" AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "VirusScanStatus" AS ENUM ('PENDING', 'SCANNING', 'CLEAN', 'INFECTED', 'QUARANTINED', 'SCAN_FAILED');

-- CreateTable
CREATE TABLE "Position" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "order" INTEGER NOT NULL DEFAULT 0,
    "maxSelections" INTEGER NOT NULL DEFAULT 1,
    "minSelections" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "Position_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vote" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "positionId" TEXT NOT NULL,
    "candidateId" TEXT,
    "voterId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "voteHash" TEXT NOT NULL,
    "encryptedVote" TEXT,
    "isAbstain" BOOLEAN NOT NULL DEFAULT false,
    "verificationCode" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "verifiedAt" TIMESTAMP(3),
    "castAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Vote_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VotingSession" (
    "id" TEXT NOT NULL,
    "voterId" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "deviceFingerprint" TEXT,
    "status" "SessionStatus" NOT NULL DEFAULT 'ACTIVE',
    "completedAt" TIMESTAMP(3),
    "sessionToken" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastActivityAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VotingSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Result" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "positionId" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "totalVotes" INTEGER NOT NULL DEFAULT 0,
    "percentage" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "rank" INTEGER NOT NULL DEFAULT 0,
    "isWinner" BOOLEAN NOT NULL DEFAULT false,
    "isTie" BOOLEAN NOT NULL DEFAULT false,
    "calculatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "publishedAt" TIMESTAMP(3),

    CONSTRAINT "Result_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "electionId" TEXT,
    "action" TEXT NOT NULL,
    "category" "AuditCategory" NOT NULL,
    "severity" "AuditSeverity" NOT NULL,
    "entityType" TEXT,
    "entityId" TEXT,
    "oldData" JSONB,
    "newData" JSONB,
    "metadata" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "requestId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "type" "NotificationType" NOT NULL,
    "priority" "NotificationPriority" NOT NULL,
    "data" JSONB,
    "actionUrl" TEXT,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "readAt" TIMESTAMP(3),
    "channels" TEXT[],
    "emailSent" BOOLEAN NOT NULL DEFAULT false,
    "smsSent" BOOLEAN NOT NULL DEFAULT false,
    "pushSent" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ElectionNotification" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "scheduledFor" TIMESTAMP(3) NOT NULL,
    "sent" BOOLEAN NOT NULL DEFAULT false,
    "sentAt" TIMESTAMP(3),
    "subject" TEXT NOT NULL,
    "template" TEXT NOT NULL,
    "data" JSONB,

    CONSTRAINT "ElectionNotification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SystemConfig" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL,
    "isPublic" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SystemConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "replacedByToken" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,

    CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "TokenType" NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VerificationToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VoterEligibility" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "addedBy" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT,

    CONSTRAINT "VoterEligibility_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "File" (
    "id" TEXT NOT NULL,
    "originalName" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "mimeType" TEXT NOT NULL,
    "category" "FileCategory" NOT NULL,
    "subCategory" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "metadata" JSONB,
    "checksum" TEXT,
    "thumbnailUrl" TEXT,
    "isPublic" BOOLEAN NOT NULL DEFAULT false,
    "downloadCount" INTEGER NOT NULL DEFAULT 0,
    "isEncrypted" BOOLEAN NOT NULL DEFAULT false,
    "accessLevel" "AccessLevel" NOT NULL DEFAULT 'PUBLIC',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastAccessed" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "uploadedById" TEXT,

    CONSTRAINT "File_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Analytics" (
    "id" TEXT NOT NULL,
    "eventType" "AnalyticsEventType" NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT,
    "userId" TEXT,
    "sessionId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "deviceType" TEXT,
    "browser" TEXT,
    "os" TEXT,
    "country" TEXT,
    "region" TEXT,
    "city" TEXT,
    "eventData" JSONB,
    "duration" INTEGER,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "date" DATE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Analytics_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Backup" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "type" "BackupType" NOT NULL,
    "status" "BackupStatus" NOT NULL DEFAULT 'PENDING',
    "filePath" TEXT,
    "fileSize" INTEGER,
    "checksum" TEXT,
    "tables" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "recordCount" INTEGER,
    "compressionRatio" DOUBLE PRECISION,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "duration" INTEGER,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "Backup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Achievement" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "type" "AchievementType" NOT NULL,
    "icon" TEXT,
    "badgeColor" TEXT,
    "criteria" JSONB NOT NULL,
    "points" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Achievement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserAchievement" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "achievementId" TEXT NOT NULL,
    "progress" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "completed" BOOLEAN NOT NULL DEFAULT false,
    "completedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserAchievement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SocialMedia" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "platform" "SocialPlatform" NOT NULL,
    "username" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "isPublic" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SocialMedia_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserPreferences" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "emailNotifications" BOOLEAN NOT NULL DEFAULT true,
    "smsNotifications" BOOLEAN NOT NULL DEFAULT false,
    "pushNotifications" BOOLEAN NOT NULL DEFAULT true,
    "electionReminders" BOOLEAN NOT NULL DEFAULT true,
    "resultNotifications" BOOLEAN NOT NULL DEFAULT true,
    "campaignUpdates" BOOLEAN NOT NULL DEFAULT false,
    "profileVisibility" "ProfileVisibility" NOT NULL DEFAULT 'PUBLIC',
    "showVotingHistory" BOOLEAN NOT NULL DEFAULT false,
    "showAchievements" BOOLEAN NOT NULL DEFAULT true,
    "theme" "Theme" NOT NULL DEFAULT 'LIGHT',
    "language" TEXT NOT NULL DEFAULT 'en',
    "timezone" TEXT NOT NULL DEFAULT 'UTC',
    "highContrast" BOOLEAN NOT NULL DEFAULT false,
    "largeFonts" BOOLEAN NOT NULL DEFAULT false,
    "screenReader" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserPreferences_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IssueReport" (
    "id" TEXT NOT NULL,
    "reportedBy" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" "IssueCategory" NOT NULL,
    "priority" "IssuePriority" NOT NULL DEFAULT 'MEDIUM',
    "status" "IssueStatus" NOT NULL DEFAULT 'OPEN',
    "page" TEXT,
    "userAgent" TEXT,
    "errorDetails" JSONB,
    "screenshots" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "assignedTo" TEXT,
    "resolvedBy" TEXT,
    "resolution" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IssueReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Campaign" (
    "id" TEXT NOT NULL,
    "candidateId" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slogan" TEXT,
    "description" TEXT NOT NULL,
    "manifesto" TEXT NOT NULL,
    "logo" TEXT,
    "bannerImage" TEXT,
    "colors" JSONB,
    "email" TEXT,
    "phone" TEXT,
    "website" TEXT,
    "socialMedia" JSONB,
    "status" "CampaignStatus" NOT NULL DEFAULT 'DRAFT',
    "isApproved" BOOLEAN NOT NULL DEFAULT false,
    "approvedBy" TEXT,
    "approvedAt" TIMESTAMP(3),
    "viewCount" INTEGER NOT NULL DEFAULT 0,
    "shareCount" INTEGER NOT NULL DEFAULT 0,
    "engagementRate" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "publishedAt" TIMESTAMP(3),

    CONSTRAINT "Campaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Task" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "type" "TaskType" NOT NULL,
    "priority" "TaskPriority" NOT NULL DEFAULT 'MEDIUM',
    "status" "TaskStatus" NOT NULL DEFAULT 'PENDING',
    "assignedTo" TEXT,
    "assignedBy" TEXT NOT NULL,
    "entityType" TEXT,
    "entityId" TEXT,
    "dueDate" TIMESTAMP(3),
    "estimatedHours" DOUBLE PRECISION,
    "actualHours" DOUBLE PRECISION,
    "completedAt" TIMESTAMP(3),
    "completedBy" TEXT,
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Task_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "studentId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "middleName" TEXT,
    "password" TEXT NOT NULL,
    "phone" TEXT,
    "profileImage" TEXT,
    "bio" TEXT,
    "faculty" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "course" TEXT NOT NULL,
    "yearOfStudy" INTEGER NOT NULL,
    "admissionYear" INTEGER NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerified" TIMESTAMP(3),
    "phoneVerified" TIMESTAMP(3),
    "role" "UserRole" NOT NULL DEFAULT 'VOTER',
    "permissions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "passwordResetToken" TEXT,
    "passwordResetExpires" TIMESTAMP(3),
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" TEXT,
    "lastLogin" TIMESTAMP(3),
    "loginAttempts" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Election" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "type" "ElectionType" NOT NULL,
    "status" "ElectionStatus" NOT NULL DEFAULT 'DRAFT',
    "startDate" TIMESTAMP(3) NOT NULL,
    "endDate" TIMESTAMP(3) NOT NULL,
    "registrationStart" TIMESTAMP(3),
    "registrationEnd" TIMESTAMP(3),
    "eligibleFaculties" TEXT[],
    "eligibleDepartments" TEXT[],
    "eligibleCourses" TEXT[],
    "eligibleYears" INTEGER[],
    "minVoterAge" INTEGER,
    "maxVoterAge" INTEGER,
    "maxVotesPerPosition" INTEGER NOT NULL DEFAULT 1,
    "allowAbstain" BOOLEAN NOT NULL DEFAULT true,
    "requireAllPositions" BOOLEAN NOT NULL DEFAULT false,
    "showLiveResults" BOOLEAN NOT NULL DEFAULT false,
    "requireTwoFactor" BOOLEAN NOT NULL DEFAULT false,
    "encryptVotes" BOOLEAN NOT NULL DEFAULT true,
    "anonymousVoting" BOOLEAN NOT NULL DEFAULT true,
    "coverImage" TEXT,
    "rules" JSONB,
    "totalEligibleVoters" INTEGER NOT NULL DEFAULT 0,
    "totalVotesCast" INTEGER NOT NULL DEFAULT 0,
    "turnoutPercentage" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "publishedAt" TIMESTAMP(3),
    "archivedAt" TIMESTAMP(3),
    "createdById" TEXT NOT NULL,

    CONSTRAINT "Election_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Candidate" (
    "id" TEXT NOT NULL,
    "electionId" TEXT NOT NULL,
    "positionId" TEXT NOT NULL,
    "studentId" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "middleName" TEXT,
    "email" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "faculty" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "course" TEXT NOT NULL,
    "yearOfStudy" INTEGER NOT NULL,
    "manifesto" TEXT NOT NULL,
    "slogan" TEXT,
    "photo" TEXT NOT NULL,
    "bannerImage" TEXT,
    "socialMedia" JSONB,
    "runningMateId" TEXT,
    "status" "CandidateStatus" NOT NULL DEFAULT 'PENDING',
    "verifiedAt" TIMESTAMP(3),
    "disqualifiedAt" TIMESTAMP(3),
    "disqualificationReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Candidate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityEvent" (
    "id" TEXT NOT NULL,
    "type" "SecurityEventType" NOT NULL,
    "severity" "AuditSeverity" NOT NULL,
    "description" TEXT NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT,
    "riskScore" DOUBLE PRECISION,
    "blocked" BOOLEAN NOT NULL DEFAULT false,
    "resolved" BOOLEAN NOT NULL DEFAULT false,
    "resolvedBy" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CryptoKey" (
    "id" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "keyType" "CryptoKeyType" NOT NULL,
    "algorithm" TEXT NOT NULL,
    "encryptedKey" TEXT NOT NULL,
    "publicKey" TEXT,
    "keySize" INTEGER NOT NULL,
    "purpose" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT,
    "rotationSchedule" TEXT,
    "lastRotated" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CryptoKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityHash" (
    "id" TEXT NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "hashValue" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'SHA-256',
    "salt" TEXT,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "verifiedAt" TIMESTAMP(3),
    "verifiedBy" TEXT,
    "previousHash" TEXT,
    "blockNumber" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityHash_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebSocketConnection" (
    "id" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "userId" TEXT,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT,
    "sessionId" TEXT,
    "roomId" TEXT,
    "status" "ConnectionStatus" NOT NULL DEFAULT 'CONNECTED',
    "lastPing" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "connectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "disconnectedAt" TIMESTAMP(3),

    CONSTRAINT "WebSocketConnection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DashboardWidget" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "widgetType" "WidgetType" NOT NULL,
    "position" JSONB NOT NULL,
    "configuration" JSONB,
    "isVisible" BOOLEAN NOT NULL DEFAULT true,
    "order" INTEGER NOT NULL DEFAULT 0,
    "accessLevel" "AccessLevel" NOT NULL DEFAULT 'AUTHENTICATED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DashboardWidget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReportTemplate" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "type" "ReportType" NOT NULL,
    "format" "ReportFormat"[] DEFAULT ARRAY['PDF']::"ReportFormat"[],
    "parameters" JSONB NOT NULL,
    "isScheduled" BOOLEAN NOT NULL DEFAULT false,
    "scheduleExpression" TEXT,
    "isPublic" BOOLEAN NOT NULL DEFAULT false,
    "accessRoles" "UserRole"[] DEFAULT ARRAY[]::"UserRole"[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdById" TEXT NOT NULL,

    CONSTRAINT "ReportTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GeneratedReport" (
    "id" TEXT NOT NULL,
    "templateId" TEXT,
    "name" TEXT NOT NULL,
    "type" "ReportType" NOT NULL,
    "format" "ReportFormat" NOT NULL,
    "filePath" TEXT,
    "fileSize" INTEGER,
    "downloadCount" INTEGER NOT NULL DEFAULT 0,
    "status" "ReportStatus" NOT NULL DEFAULT 'GENERATING',
    "parameters" JSONB,
    "generationTime" INTEGER,
    "errorMessage" TEXT,
    "isPublic" BOOLEAN NOT NULL DEFAULT false,
    "accessUsers" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "requestedById" TEXT NOT NULL,

    CONSTRAINT "GeneratedReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FileMetadata" (
    "id" TEXT NOT NULL,
    "fileId" TEXT NOT NULL,
    "processingStatus" "FileProcessingStatus" NOT NULL DEFAULT 'PENDING',
    "processedAt" TIMESTAMP(3),
    "width" INTEGER,
    "height" INTEGER,
    "pages" INTEGER,
    "duration" INTEGER,
    "quality" TEXT,
    "compressionRatio" DOUBLE PRECISION,
    "originalSize" INTEGER,
    "virusScanStatus" "VirusScanStatus" NOT NULL DEFAULT 'PENDING',
    "virusScanResult" TEXT,
    "scannedAt" TIMESTAMP(3),
    "contentType" TEXT,
    "extractedText" TEXT,
    "keywords" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FileMetadata_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_ProfileImage" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "_ElectionAdmin" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "_ElectionCover" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "_CandidatePhoto" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "_CandidateBanner" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "_CandidateManifesto" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateIndex
CREATE INDEX "Position_electionId_idx" ON "Position"("electionId");

-- CreateIndex
CREATE UNIQUE INDEX "Position_electionId_name_key" ON "Position"("electionId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Vote_voteHash_key" ON "Vote"("voteHash");

-- CreateIndex
CREATE UNIQUE INDEX "Vote_verificationCode_key" ON "Vote"("verificationCode");

-- CreateIndex
CREATE INDEX "Vote_electionId_positionId_idx" ON "Vote"("electionId", "positionId");

-- CreateIndex
CREATE INDEX "Vote_voterId_idx" ON "Vote"("voterId");

-- CreateIndex
CREATE INDEX "Vote_voteHash_idx" ON "Vote"("voteHash");

-- CreateIndex
CREATE UNIQUE INDEX "Vote_electionId_positionId_voterId_key" ON "Vote"("electionId", "positionId", "voterId");

-- CreateIndex
CREATE UNIQUE INDEX "VotingSession_sessionToken_key" ON "VotingSession"("sessionToken");

-- CreateIndex
CREATE INDEX "VotingSession_voterId_electionId_idx" ON "VotingSession"("voterId", "electionId");

-- CreateIndex
CREATE INDEX "VotingSession_sessionToken_idx" ON "VotingSession"("sessionToken");

-- CreateIndex
CREATE INDEX "Result_electionId_positionId_idx" ON "Result"("electionId", "positionId");

-- CreateIndex
CREATE UNIQUE INDEX "Result_electionId_positionId_candidateId_key" ON "Result"("electionId", "positionId", "candidateId");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_electionId_idx" ON "AuditLog"("electionId");

-- CreateIndex
CREATE INDEX "AuditLog_category_idx" ON "AuditLog"("category");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE INDEX "Notification_userId_read_idx" ON "Notification"("userId", "read");

-- CreateIndex
CREATE INDEX "Notification_createdAt_idx" ON "Notification"("createdAt");

-- CreateIndex
CREATE INDEX "ElectionNotification_electionId_idx" ON "ElectionNotification"("electionId");

-- CreateIndex
CREATE INDEX "ElectionNotification_scheduledFor_idx" ON "ElectionNotification"("scheduledFor");

-- CreateIndex
CREATE UNIQUE INDEX "SystemConfig_key_key" ON "SystemConfig"("key");

-- CreateIndex
CREATE INDEX "SystemConfig_category_idx" ON "SystemConfig"("category");

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_token_key" ON "RefreshToken"("token");

-- CreateIndex
CREATE INDEX "RefreshToken_userId_idx" ON "RefreshToken"("userId");

-- CreateIndex
CREATE INDEX "RefreshToken_token_idx" ON "RefreshToken"("token");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_token_key" ON "VerificationToken"("token");

-- CreateIndex
CREATE INDEX "VerificationToken_token_idx" ON "VerificationToken"("token");

-- CreateIndex
CREATE INDEX "VerificationToken_userId_idx" ON "VerificationToken"("userId");

-- CreateIndex
CREATE INDEX "VoterEligibility_electionId_idx" ON "VoterEligibility"("electionId");

-- CreateIndex
CREATE INDEX "VoterEligibility_userId_idx" ON "VoterEligibility"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "VoterEligibility_electionId_userId_key" ON "VoterEligibility"("electionId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "File_filename_key" ON "File"("filename");

-- CreateIndex
CREATE INDEX "File_category_idx" ON "File"("category");

-- CreateIndex
CREATE INDEX "File_uploadedById_idx" ON "File"("uploadedById");

-- CreateIndex
CREATE INDEX "File_createdAt_idx" ON "File"("createdAt");

-- CreateIndex
CREATE INDEX "File_mimeType_idx" ON "File"("mimeType");

-- CreateIndex
CREATE INDEX "File_filename_idx" ON "File"("filename");

-- CreateIndex
CREATE INDEX "Analytics_eventType_idx" ON "Analytics"("eventType");

-- CreateIndex
CREATE INDEX "Analytics_entityType_entityId_idx" ON "Analytics"("entityType", "entityId");

-- CreateIndex
CREATE INDEX "Analytics_userId_idx" ON "Analytics"("userId");

-- CreateIndex
CREATE INDEX "Analytics_timestamp_idx" ON "Analytics"("timestamp");

-- CreateIndex
CREATE INDEX "Analytics_date_idx" ON "Analytics"("date");

-- CreateIndex
CREATE INDEX "Backup_type_idx" ON "Backup"("type");

-- CreateIndex
CREATE INDEX "Backup_status_idx" ON "Backup"("status");

-- CreateIndex
CREATE INDEX "Backup_createdAt_idx" ON "Backup"("createdAt");

-- CreateIndex
CREATE INDEX "Achievement_type_idx" ON "Achievement"("type");

-- CreateIndex
CREATE INDEX "Achievement_isActive_idx" ON "Achievement"("isActive");

-- CreateIndex
CREATE INDEX "UserAchievement_userId_idx" ON "UserAchievement"("userId");

-- CreateIndex
CREATE INDEX "UserAchievement_achievementId_idx" ON "UserAchievement"("achievementId");

-- CreateIndex
CREATE INDEX "UserAchievement_completed_idx" ON "UserAchievement"("completed");

-- CreateIndex
CREATE UNIQUE INDEX "UserAchievement_userId_achievementId_key" ON "UserAchievement"("userId", "achievementId");

-- CreateIndex
CREATE INDEX "SocialMedia_userId_idx" ON "SocialMedia"("userId");

-- CreateIndex
CREATE INDEX "SocialMedia_platform_idx" ON "SocialMedia"("platform");

-- CreateIndex
CREATE UNIQUE INDEX "SocialMedia_userId_platform_key" ON "SocialMedia"("userId", "platform");

-- CreateIndex
CREATE UNIQUE INDEX "UserPreferences_userId_key" ON "UserPreferences"("userId");

-- CreateIndex
CREATE INDEX "UserPreferences_userId_idx" ON "UserPreferences"("userId");

-- CreateIndex
CREATE INDEX "IssueReport_reportedBy_idx" ON "IssueReport"("reportedBy");

-- CreateIndex
CREATE INDEX "IssueReport_status_idx" ON "IssueReport"("status");

-- CreateIndex
CREATE INDEX "IssueReport_category_idx" ON "IssueReport"("category");

-- CreateIndex
CREATE INDEX "IssueReport_priority_idx" ON "IssueReport"("priority");

-- CreateIndex
CREATE INDEX "IssueReport_createdAt_idx" ON "IssueReport"("createdAt");

-- CreateIndex
CREATE INDEX "Campaign_electionId_idx" ON "Campaign"("electionId");

-- CreateIndex
CREATE INDEX "Campaign_status_idx" ON "Campaign"("status");

-- CreateIndex
CREATE INDEX "Campaign_isApproved_idx" ON "Campaign"("isApproved");

-- CreateIndex
CREATE UNIQUE INDEX "Campaign_candidateId_key" ON "Campaign"("candidateId");

-- CreateIndex
CREATE INDEX "Task_assignedTo_idx" ON "Task"("assignedTo");

-- CreateIndex
CREATE INDEX "Task_assignedBy_idx" ON "Task"("assignedBy");

-- CreateIndex
CREATE INDEX "Task_status_idx" ON "Task"("status");

-- CreateIndex
CREATE INDEX "Task_type_idx" ON "Task"("type");

-- CreateIndex
CREATE INDEX "Task_dueDate_idx" ON "Task"("dueDate");

-- CreateIndex
CREATE INDEX "Task_entityType_entityId_idx" ON "Task"("entityType", "entityId");

-- CreateIndex
CREATE UNIQUE INDEX "User_studentId_key" ON "User"("studentId");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_studentId_idx" ON "User"("studentId");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_role_idx" ON "User"("role");

-- CreateIndex
CREATE INDEX "Election_status_idx" ON "Election"("status");

-- CreateIndex
CREATE INDEX "Election_type_idx" ON "Election"("type");

-- CreateIndex
CREATE INDEX "Election_startDate_endDate_idx" ON "Election"("startDate", "endDate");

-- CreateIndex
CREATE UNIQUE INDEX "Candidate_runningMateId_key" ON "Candidate"("runningMateId");

-- CreateIndex
CREATE INDEX "Candidate_electionId_positionId_idx" ON "Candidate"("electionId", "positionId");

-- CreateIndex
CREATE INDEX "Candidate_status_idx" ON "Candidate"("status");

-- CreateIndex
CREATE UNIQUE INDEX "Candidate_electionId_positionId_studentId_key" ON "Candidate"("electionId", "positionId", "studentId");

-- CreateIndex
CREATE INDEX "SecurityEvent_type_idx" ON "SecurityEvent"("type");

-- CreateIndex
CREATE INDEX "SecurityEvent_severity_idx" ON "SecurityEvent"("severity");

-- CreateIndex
CREATE INDEX "SecurityEvent_userId_idx" ON "SecurityEvent"("userId");

-- CreateIndex
CREATE INDEX "SecurityEvent_createdAt_idx" ON "SecurityEvent"("createdAt");

-- CreateIndex
CREATE INDEX "SecurityEvent_resolved_idx" ON "SecurityEvent"("resolved");

-- CreateIndex
CREATE UNIQUE INDEX "CryptoKey_keyId_key" ON "CryptoKey"("keyId");

-- CreateIndex
CREATE INDEX "CryptoKey_keyType_idx" ON "CryptoKey"("keyType");

-- CreateIndex
CREATE INDEX "CryptoKey_purpose_idx" ON "CryptoKey"("purpose");

-- CreateIndex
CREATE INDEX "CryptoKey_isActive_idx" ON "CryptoKey"("isActive");

-- CreateIndex
CREATE INDEX "CryptoKey_expiresAt_idx" ON "CryptoKey"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityHash_hashValue_key" ON "SecurityHash"("hashValue");

-- CreateIndex
CREATE INDEX "SecurityHash_entityType_entityId_idx" ON "SecurityHash"("entityType", "entityId");

-- CreateIndex
CREATE INDEX "SecurityHash_hashValue_idx" ON "SecurityHash"("hashValue");

-- CreateIndex
CREATE INDEX "SecurityHash_verified_idx" ON "SecurityHash"("verified");

-- CreateIndex
CREATE INDEX "SecurityHash_blockNumber_idx" ON "SecurityHash"("blockNumber");

-- CreateIndex
CREATE UNIQUE INDEX "WebSocketConnection_connectionId_key" ON "WebSocketConnection"("connectionId");

-- CreateIndex
CREATE INDEX "WebSocketConnection_userId_idx" ON "WebSocketConnection"("userId");

-- CreateIndex
CREATE INDEX "WebSocketConnection_status_idx" ON "WebSocketConnection"("status");

-- CreateIndex
CREATE INDEX "WebSocketConnection_roomId_idx" ON "WebSocketConnection"("roomId");

-- CreateIndex
CREATE INDEX "WebSocketConnection_connectedAt_idx" ON "WebSocketConnection"("connectedAt");

-- CreateIndex
CREATE INDEX "DashboardWidget_userId_idx" ON "DashboardWidget"("userId");

-- CreateIndex
CREATE INDEX "DashboardWidget_widgetType_idx" ON "DashboardWidget"("widgetType");

-- CreateIndex
CREATE INDEX "DashboardWidget_isVisible_idx" ON "DashboardWidget"("isVisible");

-- CreateIndex
CREATE INDEX "ReportTemplate_type_idx" ON "ReportTemplate"("type");

-- CreateIndex
CREATE INDEX "ReportTemplate_isScheduled_idx" ON "ReportTemplate"("isScheduled");

-- CreateIndex
CREATE INDEX "ReportTemplate_createdById_idx" ON "ReportTemplate"("createdById");

-- CreateIndex
CREATE INDEX "GeneratedReport_type_idx" ON "GeneratedReport"("type");

-- CreateIndex
CREATE INDEX "GeneratedReport_status_idx" ON "GeneratedReport"("status");

-- CreateIndex
CREATE INDEX "GeneratedReport_requestedById_idx" ON "GeneratedReport"("requestedById");

-- CreateIndex
CREATE INDEX "GeneratedReport_generatedAt_idx" ON "GeneratedReport"("generatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "FileMetadata_fileId_key" ON "FileMetadata"("fileId");

-- CreateIndex
CREATE INDEX "FileMetadata_processingStatus_idx" ON "FileMetadata"("processingStatus");

-- CreateIndex
CREATE INDEX "FileMetadata_virusScanStatus_idx" ON "FileMetadata"("virusScanStatus");

-- CreateIndex
CREATE INDEX "FileMetadata_contentType_idx" ON "FileMetadata"("contentType");

-- CreateIndex
CREATE UNIQUE INDEX "_ProfileImage_AB_unique" ON "_ProfileImage"("A", "B");

-- CreateIndex
CREATE INDEX "_ProfileImage_B_index" ON "_ProfileImage"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_ElectionAdmin_AB_unique" ON "_ElectionAdmin"("A", "B");

-- CreateIndex
CREATE INDEX "_ElectionAdmin_B_index" ON "_ElectionAdmin"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_ElectionCover_AB_unique" ON "_ElectionCover"("A", "B");

-- CreateIndex
CREATE INDEX "_ElectionCover_B_index" ON "_ElectionCover"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CandidatePhoto_AB_unique" ON "_CandidatePhoto"("A", "B");

-- CreateIndex
CREATE INDEX "_CandidatePhoto_B_index" ON "_CandidatePhoto"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CandidateBanner_AB_unique" ON "_CandidateBanner"("A", "B");

-- CreateIndex
CREATE INDEX "_CandidateBanner_B_index" ON "_CandidateBanner"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CandidateManifesto_AB_unique" ON "_CandidateManifesto"("A", "B");

-- CreateIndex
CREATE INDEX "_CandidateManifesto_B_index" ON "_CandidateManifesto"("B");

-- AddForeignKey
ALTER TABLE "Position" ADD CONSTRAINT "Position_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vote" ADD CONSTRAINT "Vote_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vote" ADD CONSTRAINT "Vote_positionId_fkey" FOREIGN KEY ("positionId") REFERENCES "Position"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vote" ADD CONSTRAINT "Vote_candidateId_fkey" FOREIGN KEY ("candidateId") REFERENCES "Candidate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vote" ADD CONSTRAINT "Vote_voterId_fkey" FOREIGN KEY ("voterId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vote" ADD CONSTRAINT "Vote_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "VotingSession"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VotingSession" ADD CONSTRAINT "VotingSession_voterId_fkey" FOREIGN KEY ("voterId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VotingSession" ADD CONSTRAINT "VotingSession_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Result" ADD CONSTRAINT "Result_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Result" ADD CONSTRAINT "Result_positionId_fkey" FOREIGN KEY ("positionId") REFERENCES "Position"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Result" ADD CONSTRAINT "Result_candidateId_fkey" FOREIGN KEY ("candidateId") REFERENCES "Candidate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ElectionNotification" ADD CONSTRAINT "ElectionNotification_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VerificationToken" ADD CONSTRAINT "VerificationToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VoterEligibility" ADD CONSTRAINT "VoterEligibility_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VoterEligibility" ADD CONSTRAINT "VoterEligibility_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "File" ADD CONSTRAINT "File_uploadedById_fkey" FOREIGN KEY ("uploadedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Analytics" ADD CONSTRAINT "Analytics_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Backup" ADD CONSTRAINT "Backup_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAchievement" ADD CONSTRAINT "UserAchievement_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAchievement" ADD CONSTRAINT "UserAchievement_achievementId_fkey" FOREIGN KEY ("achievementId") REFERENCES "Achievement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SocialMedia" ADD CONSTRAINT "SocialMedia_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserPreferences" ADD CONSTRAINT "UserPreferences_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IssueReport" ADD CONSTRAINT "IssueReport_reportedBy_fkey" FOREIGN KEY ("reportedBy") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IssueReport" ADD CONSTRAINT "IssueReport_assignedTo_fkey" FOREIGN KEY ("assignedTo") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IssueReport" ADD CONSTRAINT "IssueReport_resolvedBy_fkey" FOREIGN KEY ("resolvedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Campaign" ADD CONSTRAINT "Campaign_candidateId_fkey" FOREIGN KEY ("candidateId") REFERENCES "Candidate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Campaign" ADD CONSTRAINT "Campaign_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Campaign" ADD CONSTRAINT "Campaign_approvedBy_fkey" FOREIGN KEY ("approvedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_assignedTo_fkey" FOREIGN KEY ("assignedTo") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_assignedBy_fkey" FOREIGN KEY ("assignedBy") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_completedBy_fkey" FOREIGN KEY ("completedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Election" ADD CONSTRAINT "Election_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Candidate" ADD CONSTRAINT "Candidate_runningMateId_fkey" FOREIGN KEY ("runningMateId") REFERENCES "Candidate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Candidate" ADD CONSTRAINT "Candidate_electionId_fkey" FOREIGN KEY ("electionId") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Candidate" ADD CONSTRAINT "Candidate_positionId_fkey" FOREIGN KEY ("positionId") REFERENCES "Position"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_resolvedBy_fkey" FOREIGN KEY ("resolvedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CryptoKey" ADD CONSTRAINT "CryptoKey_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityHash" ADD CONSTRAINT "SecurityHash_verifiedBy_fkey" FOREIGN KEY ("verifiedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WebSocketConnection" ADD CONSTRAINT "WebSocketConnection_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DashboardWidget" ADD CONSTRAINT "DashboardWidget_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReportTemplate" ADD CONSTRAINT "ReportTemplate_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GeneratedReport" ADD CONSTRAINT "GeneratedReport_templateId_fkey" FOREIGN KEY ("templateId") REFERENCES "ReportTemplate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GeneratedReport" ADD CONSTRAINT "GeneratedReport_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FileMetadata" ADD CONSTRAINT "FileMetadata_fileId_fkey" FOREIGN KEY ("fileId") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ProfileImage" ADD CONSTRAINT "_ProfileImage_A_fkey" FOREIGN KEY ("A") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ProfileImage" ADD CONSTRAINT "_ProfileImage_B_fkey" FOREIGN KEY ("B") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ElectionAdmin" ADD CONSTRAINT "_ElectionAdmin_A_fkey" FOREIGN KEY ("A") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ElectionAdmin" ADD CONSTRAINT "_ElectionAdmin_B_fkey" FOREIGN KEY ("B") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ElectionCover" ADD CONSTRAINT "_ElectionCover_A_fkey" FOREIGN KEY ("A") REFERENCES "Election"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ElectionCover" ADD CONSTRAINT "_ElectionCover_B_fkey" FOREIGN KEY ("B") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidatePhoto" ADD CONSTRAINT "_CandidatePhoto_A_fkey" FOREIGN KEY ("A") REFERENCES "Candidate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidatePhoto" ADD CONSTRAINT "_CandidatePhoto_B_fkey" FOREIGN KEY ("B") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidateBanner" ADD CONSTRAINT "_CandidateBanner_A_fkey" FOREIGN KEY ("A") REFERENCES "Candidate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidateBanner" ADD CONSTRAINT "_CandidateBanner_B_fkey" FOREIGN KEY ("B") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidateManifesto" ADD CONSTRAINT "_CandidateManifesto_A_fkey" FOREIGN KEY ("A") REFERENCES "Candidate"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CandidateManifesto" ADD CONSTRAINT "_CandidateManifesto_B_fkey" FOREIGN KEY ("B") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;
