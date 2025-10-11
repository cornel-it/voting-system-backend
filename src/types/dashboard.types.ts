// backend/src/types/dashboard.types.ts

import { UserRole, ElectionStatus, ElectionType, CandidateStatus } from '@prisma/client';

// Common Dashboard Types
export interface DashboardStats {
  totalUsers: number;
  totalElections: number;
  totalVotes: number;
  totalCandidates: number;
  activeElections: number;
  completedElections: number;
  verifiedUsers: number;
  recentActivity: ActivityItem[];
}

export interface ActivityItem {
  id: string;
  type: 'user_registration' | 'election_created' | 'vote_cast' | 'candidate_registered' | 'election_started' | 'election_ended';
  description: string;
  userId?: string;
  electionId?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
}

// Voter Dashboard Types
export interface VoterDashboardData {
  profile: VoterProfile;
  eligibleElections: EligibleElection[];
  votingHistory: VotingHistoryItem[];
  notifications: DashboardNotification[];
  upcomingElections: UpcomingElection[];
  recentResults: RecentResult[];
  statistics: VoterStatistics;
}

export interface VoterProfile {
  id: string;
  studentId: string;
  firstName: string;
  lastName: string;
  email: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  profileImage?: string;
  isVerified: boolean;
  joinedAt: Date;
}

export interface EligibleElection {
  id: string;
  title: string;
  description: string;
  type: ElectionType;
  status: ElectionStatus;
  startDate: Date;
  endDate: Date;
  totalPositions: number;
  hasVoted: boolean;
  canVote: boolean;
  timeRemaining?: {
    days: number;
    hours: number;
    minutes: number;
  };
  coverImage?: string;
  turnoutPercentage: number;
}

export interface VotingHistoryItem {
  id: string;
  electionId: string;
  electionTitle: string;
  electionType: ElectionType;
  votedAt: Date;
  positionsVoted: number;
  totalPositions: number;
  verificationCode: string;
  status: 'verified' | 'pending' | 'invalid';
}

export interface VoterStatistics {
  totalElectionsParticipated: number;
  totalVotesCast: number;
  participationRate: number;
  lastVoteDate?: Date;
  averageVotingTime: number;
  favoriteElectionType: ElectionType;
  yearlyParticipation: Array<{
    year: number;
    elections: number;
    votes: number;
  }>;
}

// Candidate Dashboard Types
export interface CandidateDashboardData {
  profile: CandidateProfile;
  applications: CandidateApplication[];
  campaigns: Campaign[];
  elections: CandidateElection[];
  analytics: CandidateAnalytics;
  notifications: DashboardNotification[];
  tasks: CandidateTask[];
}

export interface CandidateProfile {
  id: string;
  studentId: string;
  firstName: string;
  lastName: string;
  email: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  profileImage?: string;
  bio?: string;
  achievements: string[];
  socialMedia?: Record<string, string>;
}

export interface CandidateApplication {
  id: string;
  electionId: string;
  electionTitle: string;
  positionId: string;
  positionName: string;
  status: CandidateStatus;
  appliedAt: Date;
  reviewedAt?: Date;
  reviewedBy?: string;
  feedback?: string;
  manifesto: string;
  photo?: string;
  bannerImage?: string;
  socialMedia?: Record<string, string>;
}

export interface Campaign {
  candidateId: string;
  electionId: string;
  electionTitle: string;
  positionName: string;
  campaignStatus: 'planning' | 'active' | 'ended';
  launchDate?: Date;
  endDate?: Date;
  manifesto: string;
  slogan?: string;
  materials: CampaignMaterial[];
  events: CampaignEvent[];
  endorsements: Endorsement[];
}

export interface CampaignMaterial {
  id: string;
  type: 'poster' | 'flyer' | 'video' | 'audio' | 'document';
  title: string;
  description?: string;
  fileUrl: string;
  thumbnailUrl?: string;
  uploadedAt: Date;
  downloads: number;
  views: number;
}

export interface CampaignEvent {
  id: string;
  title: string;
  description: string;
  type: 'rally' | 'debate' | 'meet_and_greet' | 'online_session';
  venue?: string;
  virtualLink?: string;
  startDate: Date;
  endDate: Date;
  attendees: number;
  maxAttendees?: number;
  status: 'scheduled' | 'ongoing' | 'completed' | 'cancelled';
}

export interface Endorsement {
  id: string;
  endorserName: string;
  endorserTitle: string;
  message: string;
  endorsedAt: Date;
  isPublic: boolean;
}

export interface CandidateElection {
  id: string;
  title: string;
  type: ElectionType;
  status: ElectionStatus;
  positionName: string;
  isRunningMate: boolean;
  runningMateFor?: string;
  startDate: Date;
  endDate: Date;
  totalVotes?: number;
  votePercentage?: number;
  rank?: number;
  isWinner?: boolean;
  result?: 'won' | 'lost' | 'tie' | 'pending';
}

export interface CandidateAnalytics {
  profileViews: number;
  manifestoDownloads: number;
  campaignReach: number;
  engagementRate: number;
  supporterGrowth: Array<{
    date: string;
    supporters: number;
  }>;
  demographicBreakdown: {
    byFaculty: Array<{ faculty: string; percentage: number }>;
    byYear: Array<{ year: number; percentage: number }>;
    byGender: Array<{ gender: string; percentage: number }>;
  };
  competitorComparison?: Array<{
    candidateName: string;
    votePercentage: number;
    supporterCount: number;
  }>;
}

export interface CandidateTask {
  id: string;
  title: string;
  description: string;
  type: 'application' | 'verification' | 'campaign' | 'compliance';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  status: 'pending' | 'in_progress' | 'completed' | 'overdue';
  dueDate?: Date;
  completedAt?: Date;
  assignedBy?: string;
}

// Admin Dashboard Types
export interface AdminDashboardData {
  overview: AdminOverview;
  elections: AdminElectionSummary[];
  users: AdminUserSummary;
  candidates: AdminCandidateSummary;
  voting: AdminVotingSummary;
  system: SystemHealth;
  analytics: AdminAnalytics;
  alerts: SystemAlert[];
  recentActivity: AdminActivity[];
  reports: AvailableReport[];
}

export interface AdminOverview {
  totalUsers: number;
  totalElections: number;
  totalVotes: number;
  totalCandidates: number;
  activeElections: number;
  pendingCandidates: number;
  systemUptime: number;
  serverLoad: number;
  databaseSize: number;
  storageUsed: number;
  dailyActiveUsers: number;
  weeklyActiveUsers: number;
  monthlyActiveUsers: number;
}

export interface AdminElectionSummary {
  id: string;
  title: string;
  type: ElectionType;
  status: ElectionStatus;
  startDate: Date;
  endDate: Date;
  totalCandidates: number;
  totalVotes: number;
  eligibleVoters: number;
  turnoutPercentage: number;
  completionPercentage: number;
  issuesCount: number;
  lastActivity: Date;
}

export interface AdminUserSummary {
  totalUsers: number;
  verifiedUsers: number;
  activeUsers: number;
  newRegistrations: {
    today: number;
    thisWeek: number;
    thisMonth: number;
  };
  usersByRole: Array<{
    role: UserRole;
    count: number;
  }>;
  usersByFaculty: Array<{
    faculty: string;
    count: number;
  }>;
  pendingVerifications: number;
  suspendedUsers: number;
}

export interface AdminCandidateSummary {
  totalCandidates: number;
  pendingApprovals: number;
  approvedCandidates: number;
  rejectedCandidates: number;
  candidatesByElection: Array<{
    electionId: string;
    electionTitle: string;
    candidateCount: number;
  }>;
  candidatesByStatus: Array<{
    status: CandidateStatus;
    count: number;
  }>;
  recentApplications: Array<{
    candidateId: string;
    candidateName: string;
    electionTitle: string;
    positionName: string;
    appliedAt: Date;
  }>;
}

export interface AdminVotingSummary {
  totalVotes: number;
  votesToday: number;
  votesThisWeek: number;
  averageVotingTime: number;
  peakVotingHour: number;
  votesByElection: Array<{
    electionId: string;
    electionTitle: string;
    voteCount: number;
    turnoutPercentage: number;
  }>;
  votingTrends: Array<{
    date: string;
    votes: number;
  }>;
  deviceBreakdown: Array<{
    device: string;
    percentage: number;
  }>;
}

export interface SystemHealth {
  overall: 'healthy' | 'warning' | 'critical';
  database: {
    status: 'connected' | 'disconnected' | 'slow';
    responseTime: number;
    connections: number;
    maxConnections: number;
  };
  redis: {
    status: 'connected' | 'disconnected' | 'slow';
    memory: number;
    maxMemory: number;
    hitRate: number;
  };
  storage: {
    used: number;
    available: number;
    percentage: number;
  };
  server: {
    cpu: number;
    memory: number;
    disk: number;
    uptime: number;
  };
  websocket: {
    connections: number;
    maxConnections: number;
    messageRate: number;
  };
}

export interface AdminAnalytics {
  userEngagement: {
    dailyActiveUsers: Array<{ date: string; users: number }>;
    averageSessionDuration: number;
    bounceRate: number;
    retentionRate: number;
  };
  electionMetrics: {
    averageTurnout: number;
    completionRate: number;
    averageElectionDuration: number;
    popularElectionTypes: Array<{ type: ElectionType; count: number }>;
  };
  performanceMetrics: {
    averageResponseTime: number;
    errorRate: number;
    throughput: number;
    availability: number;
  };
  securityMetrics: {
    failedLogins: number;
    suspiciousActivity: number;
    blockedIPs: number;
    securityIncidents: number;
  };
}

export interface SystemAlert {
  id: string;
  type: 'error' | 'warning' | 'info' | 'security';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  source: string;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  actionRequired?: boolean;
  resolved?: boolean;
  resolvedBy?: string;
  resolvedAt?: Date;
  metadata?: Record<string, any>;
}

export interface AdminActivity {
  id: string;
  type: 'user_action' | 'system_event' | 'election_event' | 'security_event';
  action: string;
  description: string;
  userId?: string;
  userName?: string;
  electionId?: string;
  electionTitle?: string;
  ipAddress?: string;
  userAgent?: string;
  severity: 'low' | 'medium' | 'high';
  timestamp: Date;
  metadata?: Record<string, any>;
}

export interface AvailableReport {
  id: string;
  name: string;
  description: string;
  type: 'election' | 'user' | 'voting' | 'candidate' | 'system' | 'analytics';
  format: 'pdf' | 'excel' | 'csv' | 'json';
  parameters?: Array<{
    name: string;
    type: 'string' | 'number' | 'date' | 'boolean' | 'select';
    required: boolean;
    options?: string[];
  }>;
  lastGenerated?: Date;
  generatedBy?: string;
  fileSize?: number;
  downloadUrl?: string;
}

// Common Dashboard Types
export interface DashboardNotification {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'election' | 'vote' | 'result';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  read: boolean;
  actionUrl?: string;
  actionText?: string;
  createdAt: Date;
  expiresAt?: Date;
  data?: Record<string, any>;
}

export interface UpcomingElection {
  id: string;
  title: string;
  type: ElectionType;
  startDate: Date;
  endDate: Date;
  description: string;
  totalPositions: number;
  isEligible: boolean;
  coverImage?: string;
  registrationDeadline?: Date;
  timeUntilStart: {
    days: number;
    hours: number;
    minutes: number;
  };
}

export interface RecentResult {
  id: string;
  electionId: string;
  electionTitle: string;
  electionType: ElectionType;
  completedAt: Date;
  totalVotes: number;
  turnoutPercentage: number;
  winnersByPosition: Array<{
    positionName: string;
    winnerName: string;
    votePercentage: number;
  }>;
  participatedInElection: boolean;
}

// Dashboard Filter Types
export interface DashboardFilters {
  dateRange?: {
    startDate: Date;
    endDate: Date;
  };
  electionTypes?: ElectionType[];
  electionStatuses?: ElectionStatus[];
  faculties?: string[];
  departments?: string[];
  userRoles?: UserRole[];
  candidateStatuses?: CandidateStatus[];
}

// Real-time Dashboard Updates
export interface DashboardUpdate {
  type: 'stats' | 'notification' | 'activity' | 'alert' | 'election' | 'vote';
  data: any;
  timestamp: Date;
  targetUsers?: string[];
  targetRoles?: UserRole[];
}

// Types are exported above, no need for default export