// backend/src/types/vote.types.ts

import {
  Vote,
  VotingSession,
  SessionStatus,
  User,
  Election,
  Position,
  Candidate,
  Result
} from '@prisma/client';

// Voting Session Types
export interface StartVotingSessionRequest {
  electionId: string;
  deviceFingerprint?: string;
}

export interface StartVotingSessionResponse {
  sessionId: string;
  sessionToken: string;
  expiresAt: Date;
  ballot: ElectionBallot;
  remainingTime: number;
}

export interface VotingSessionDetails {
  id: string;
  voterId: string;
  electionId: string;
  status: SessionStatus;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;
  sessionToken: string;
  expiresAt: Date;
  startedAt: Date;
  lastActivityAt: Date;
  completedAt?: Date;
  votesSubmitted: number;
  totalPositions: number;
}

export interface ExtendSessionRequest {
  sessionId: string;
  extensionMinutes: number;
}

export interface ExtendSessionResponse {
  newExpiresAt: Date;
  remainingTime: number;
  success: boolean;
}

// Ballot Types
export interface ElectionBallot {
  electionId: string;
  electionTitle: string;
  electionDescription: string;
  positions: BallotPosition[];
  rules: BallotRules;
  voterEligibility: VoterEligibility;
}

export interface BallotPosition {
  id: string;
  name: string;
  description?: string;
  order: number;
  maxSelections: number;
  minSelections: number;
  candidates: BallotCandidate[];
  allowAbstain: boolean;
}

export interface BallotCandidate {
  id: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  photo?: string;
  manifesto?: string;
  slogan?: string;
  socialMedia?: Record<string, string>;
  runningMate?: BallotCandidate;
  isRunningMate: boolean;
  party?: string;
  faculty: string;
  department: string;
  yearOfStudy: number;
}

export interface BallotRules {
  allowAbstain: boolean;
  requireAllPositions: boolean;
  maxVotesPerPosition: number;
  requireTwoFactor: boolean;
  anonymousVoting: boolean;
  votingTimeLimit?: number;
}

export interface VoterEligibility {
  isEligible: boolean;
  reasons?: string[];
  requirements: {
    faculty?: string[];
    departments?: string[];
    courses?: string[];
    years?: number[];
    minAge?: number;
    maxAge?: number;
  };
}

// Vote Casting Types
export interface CastVoteRequest {
  sessionId: string;
  ballot: VoteBallot;
  twoFactorToken?: string;
  deviceFingerprint?: string;
}

export interface VoteBallot {
  electionId: string;
  votes: PositionVote[];
}

export interface PositionVote {
  positionId: string;
  candidateIds: string[];
  isAbstain: boolean;
}

export interface CastVoteResponse {
  success: boolean;
  voteIds: string[];
  verificationCodes: string[];
  receiptHash: string;
  timestamp: Date;
  nextSteps: {
    canContinue: boolean;
    remainingPositions: string[];
    completionUrl?: string;
  };
}

// Vote Verification Types
export interface VoteVerificationRequest {
  verificationCode: string;
}

export interface VoteVerificationResponse {
  verified: boolean;
  voteDetails: {
    electionId: string;
    electionTitle: string;
    positionName: string;
    candidateName?: string;
    isAbstain: boolean;
    castAt: Date;
    voteHash: string;
  };
  integrity: {
    hashValid: boolean;
    encryptionValid: boolean;
    sequenceValid: boolean;
  };
}

export interface VoteVerificationStatus {
  code: string;
  exists: boolean;
  verified: boolean;
  election: {
    id: string;
    title: string;
    status: string;
  };
  position: {
    id: string;
    name: string;
  };
  castAt: Date;
  canVerify: boolean;
}

// Vote Receipt Types
export interface VoteReceipt {
  id: string;
  receiptHash: string;
  electionId: string;
  electionTitle: string;
  voterId: string;
  sessionId: string;
  timestamp: Date;
  verificationUrl: string;
  positions: PositionReceipt[];
  integrity: {
    receiptHash: string;
    voteHashes: string[];
    blockchainHash?: string;
  };
  security: {
    encrypted: boolean;
    anonymized: boolean;
    deviceFingerprint: string;
  };
}

export interface PositionReceipt {
  positionId: string;
  positionName: string;
  candidateNames: string[];
  isAbstain: boolean;
  verificationCode: string;
  voteHash: string;
}

// Voting Analytics Types
export interface VotingAnalytics {
  electionId: string;
  totalEligibleVoters: number;
  totalVotesCast: number;
  turnoutPercentage: number;
  votingProgress: VotingProgressData;
  demographicBreakdown: DemographicVotingData;
  timeBasedAnalytics: TimeBasedVotingData;
  deviceAnalytics: DeviceVotingData;
  securityMetrics: VotingSecurityMetrics;
}

export interface VotingProgressData {
  hourly: Array<{
    hour: string;
    votes: number;
    cumulative: number;
    turnoutRate: number;
  }>;
  byPosition: Array<{
    positionId: string;
    positionName: string;
    votesCast: number;
    turnoutPercentage: number;
    abstainVotes: number;
  }>;
  realTimeStats: {
    activeVoters: number;
    averageVotingTime: number;
    completionRate: number;
    averageTimePerPosition: number;
  };
}

export interface DemographicVotingData {
  byFaculty: Array<{
    faculty: string;
    totalEligible: number;
    votesCast: number;
    turnoutPercentage: number;
  }>;
  byDepartment: Array<{
    department: string;
    faculty: string;
    totalEligible: number;
    votesCast: number;
    turnoutPercentage: number;
  }>;
  byYear: Array<{
    year: number;
    totalEligible: number;
    votesCast: number;
    turnoutPercentage: number;
  }>;
  byAge: Array<{
    ageRange: string;
    totalEligible: number;
    votesCast: number;
    turnoutPercentage: number;
  }>;
}

export interface TimeBasedVotingData {
  peakHours: Array<{
    hour: number;
    voteCount: number;
    isWeekend: boolean;
  }>;
  dailyTrends: Array<{
    date: string;
    votes: number;
    uniqueVoters: number;
    averageSessionTime: number;
  }>;
  sessionDurations: {
    average: number;
    median: number;
    shortest: number;
    longest: number;
    distribution: Array<{
      range: string;
      count: number;
      percentage: number;
    }>;
  };
}

export interface DeviceVotingData {
  platforms: Array<{
    platform: string;
    count: number;
    percentage: number;
  }>;
  browsers: Array<{
    browser: string;
    version?: string;
    count: number;
    percentage: number;
  }>;
  devices: Array<{
    deviceType: 'mobile' | 'tablet' | 'desktop';
    count: number;
    percentage: number;
  }>;
  locations: Array<{
    location: string;
    count: number;
    percentage: number;
  }>;
}

export interface VotingSecurityMetrics {
  duplicateAttempts: number;
  invalidSessions: number;
  suspiciousActivity: number;
  failedVerifications: number;
  encryptionFailures: number;
  integrityChecks: {
    passed: number;
    failed: number;
    warningsCount: number;
  };
  deviceFingerprinting: {
    unique: number;
    duplicates: number;
    conflicts: number;
  };
}

// Real-time Voting Types
export interface RealTimeVotingStats {
  electionId: string;
  lastUpdated: Date;
  activeVoters: number;
  completedVotes: number;
  currentTurnout: number;
  recentActivity: RecentVotingActivity[];
  positionProgress: Array<{
    positionId: string;
    positionName: string;
    votesCast: number;
    targetTurnout: number;
    progressPercentage: number;
  }>;
  systemStatus: {
    healthy: boolean;
    responseTime: number;
    queueLength: number;
    errors: number;
  };
}

export interface RecentVotingActivity {
  timestamp: Date;
  positionName: string;
  faculty: string;
  department?: string;
  anonymizedVoterId: string;
  sessionDuration: number;
}

// Vote Tallying Types
export interface VoteTallyRequest {
  electionId: string;
  includePartial?: boolean;
  recalculate?: boolean;
}

export interface VoteTallyResponse {
  electionId: string;
  totalVotesCast: number;
  totalEligibleVoters: number;
  overallTurnout: number;
  results: PositionTallyResult[];
  metadata: TallyMetadata;
  integrity: TallyIntegrityCheck;
}

export interface PositionTallyResult {
  positionId: string;
  positionName: string;
  totalVotes: number;
  validVotes: number;
  invalidVotes: number;
  abstainVotes: number;
  candidates: CandidateTallyResult[];
  winner?: CandidateTallyResult;
  isTie: boolean;
  tiedCandidates?: CandidateTallyResult[];
}

export interface CandidateTallyResult {
  candidateId: string;
  candidateName: string;
  voteCount: number;
  percentage: number;
  rank: number;
  isWinner: boolean;
  marginOfVictory?: number;
  voteDifference?: number;
}

export interface TallyMetadata {
  calculatedAt: Date;
  calculatedBy: string;
  algorithm: string;
  version: string;
  includesPartialVotes: boolean;
  verificationLevel: 'basic' | 'standard' | 'comprehensive';
}

export interface TallyIntegrityCheck {
  totalVoteCheck: boolean;
  hashVerification: boolean;
  sequentialCheck: boolean;
  duplicateCheck: boolean;
  encryptionCheck: boolean;
  warnings: string[];
  errors: string[];
}

// Vote History Types
export interface VoteHistoryRequest {
  userId: string;
  includeDetails?: boolean;
  page?: number;
  limit?: number;
}

export interface VoteHistoryResponse {
  userId: string;
  history: VoteHistoryItem[];
  statistics: VoteHistoryStatistics;
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

export interface VoteHistoryItem {
  id: string;
  electionId: string;
  electionTitle: string;
  electionType: string;
  votedAt: Date;
  positionsVoted: number;
  totalPositions: number;
  verificationCodes: string[];
  status: 'verified' | 'pending' | 'invalid';
  receiptHash: string;
  details?: {
    sessionDuration: number;
    deviceUsed: string;
    ipAddress?: string;
    verificationResults: boolean[];
  };
}

export interface VoteHistoryStatistics {
  totalElectionsParticipated: number;
  totalVotesCast: number;
  verificationRate: number;
  averageVotingTime: number;
  participationRate: number;
  lastVoteDate?: Date;
  firstVoteDate?: Date;
  yearlyParticipation: Array<{
    year: number;
    elections: number;
    votes: number;
  }>;
}

// Vote Issues and Reporting Types
export interface VotingIssueReport {
  id: string;
  userId: string;
  electionId: string;
  sessionId?: string;
  issueType: VotingIssueType;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  reportedAt: Date;
  resolvedAt?: Date;
  resolution?: string;
  ticketNumber: string;
  attachments?: string[];
  deviceInfo: {
    userAgent: string;
    platform: string;
    browser: string;
    ipAddress: string;
  };
  adminNotes?: string[];
}

export type VotingIssueType =
  | 'session_timeout'
  | 'ballot_loading_error'
  | 'vote_submission_failed'
  | 'verification_failure'
  | 'candidate_display_issue'
  | 'position_navigation_problem'
  | 'device_compatibility'
  | 'network_connectivity'
  | 'authentication_problem'
  | 'receipt_generation_failed'
  | 'other';

export interface ReportIssueRequest {
  electionId: string;
  sessionId?: string;
  issueType: VotingIssueType;
  title: string;
  description: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  attachments?: File[];
  reproductionSteps?: string[];
}

export interface ReportIssueResponse {
  issueId: string;
  ticketNumber: string;
  estimatedResolutionTime: string;
  supportContactInfo: {
    email: string;
    phone: string;
    helpDeskUrl: string;
  };
}

// Emergency Voting Types
export interface EmergencyVotingOptions {
  electionId: string;
  availableOptions: EmergencyOption[];
  systemStatus: {
    mainSystemOperational: boolean;
    backupSystemAvailable: boolean;
    estimatedDowntime?: string;
    affectedServices: string[];
  };
  contactInformation: {
    technicalSupport: string;
    emergencyHotline: string;
    alternativeVotingMethods: string[];
  };
}

export interface EmergencyOption {
  id: string;
  type: 'paper_ballot' | 'alternative_system' | 'extended_deadline' | 'emergency_access';
  title: string;
  description: string;
  available: boolean;
  requirements: string[];
  instructions: string[];
  estimatedTime: string;
  contactPerson: string;
}

// Vote Export Types
export interface VoteExportRequest {
  electionId: string;
  format: 'json' | 'csv' | 'xlsx' | 'pdf';
  includePersonalData: boolean;
  anonymizeData?: boolean;
  includeMeta?: boolean;
  dateRange?: {
    startDate: Date;
    endDate: Date;
  };
  filters?: {
    positions?: string[];
    faculties?: string[];
    departments?: string[];
    verified?: boolean;
  };
}

export interface VoteExportResponse {
  exportId: string;
  filename: string;
  format: string;
  size: number;
  mimeType: string;
  downloadUrl: string;
  expiresAt: Date;
  metadata: {
    totalRecords: number;
    exportedAt: Date;
    exportedBy: string;
    includesPersonalData: boolean;
    anonymized: boolean;
  };
  data?: any; // For JSON format
  buffer?: Buffer; // For binary formats
}

// Batch Vote Operations Types
export interface BatchVoteOperation {
  operationType: 'invalidate' | 'verify' | 'recount' | 'export';
  voteIds: string[];
  reason: string;
  metadata?: Record<string, any>;
}

export interface BatchVoteResult {
  operation: string;
  totalProcessed: number;
  successful: number;
  failed: number;
  results: Array<{
    voteId: string;
    success: boolean;
    error?: string;
    previousState?: any;
    newState?: any;
  }>;
  completedAt: Date;
  processingTime: number;
}

// Vote Validation Types
export interface BallotValidationRequest {
  electionId: string;
  ballot: VoteBallot;
  sessionId: string;
}

export interface BallotValidationResponse {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  summary: {
    totalPositions: number;
    validPositions: number;
    invalidPositions: number;
    totalCandidatesSelected: number;
    abstainedPositions: number;
  };
}

export interface ValidationError {
  positionId?: string;
  positionName?: string;
  candidateId?: string;
  errorType: ValidationErrorType;
  message: string;
  field?: string;
}

export interface ValidationWarning {
  positionId?: string;
  positionName?: string;
  warningType: string;
  message: string;
}

export type ValidationErrorType =
  | 'required_position_missing'
  | 'too_many_selections'
  | 'too_few_selections'
  | 'invalid_candidate'
  | 'duplicate_selection'
  | 'position_not_found'
  | 'candidate_not_eligible'
  | 'session_expired'
  | 'election_not_active'
  | 'voter_not_eligible'
  | 'already_voted';

// Types are exported above, no need for default export