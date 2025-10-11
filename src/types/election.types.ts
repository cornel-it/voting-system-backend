// backend/src/types/election.types.ts

import {
  Election,
  ElectionType,
  ElectionStatus,
  Position,
  Candidate,
  Vote,
  Result,
  User
} from '@prisma/client';

export interface CreateElectionData {
  title: string;
  description: string;
  type: ElectionType;
  startDate: Date;
  endDate: Date;
  registrationStart?: Date;
  registrationEnd?: Date;
  eligibleFaculties?: string[];
  eligibleDepartments?: string[];
  eligibleCourses?: string[];
  eligibleYears?: number[];
  minVoterAge?: number;
  maxVoterAge?: number;
  maxVotesPerPosition?: number;
  allowAbstain?: boolean;
  requireAllPositions?: boolean;
  showLiveResults?: boolean;
  requireTwoFactor?: boolean;
  encryptVotes?: boolean;
  anonymousVoting?: boolean;
  coverImage?: string;
  rules?: any;
  positions: CreatePositionData[];
}

export interface CreatePositionData {
  name: string;
  description?: string;
  order: number;
  maxSelections: number;
  minSelections: number;
}

export interface UpdateElectionData extends Partial<CreateElectionData> {
  status?: ElectionStatus;
}

export interface ElectionWithRelations extends Election {
  positions: (Position & {
    candidates?: (Candidate & {
      user?: Partial<User>;
    })[];
  })[];
  candidates: (Candidate & {
    position?: Position;
    user?: Partial<User>;
  })[];
  votes: Partial<Vote>[];
  results: (Result & {
    candidate?: Candidate;
    position?: Position;
  })[];
  creator: Partial<User>;
  admins: Partial<User>[];
}

export interface ElectionStats {
  totalEligibleVoters: number;
  totalVotesCast: number;
  turnoutPercentage: number;
  positionStats: PositionStats[];
  timeStats: TimeStats;
  demographicStats: DemographicStats;
}

export interface PositionStats {
  positionId: string;
  positionName: string;
  totalCandidates: number;
  totalVotes: number;
  turnoutPercentage: number;
}

export interface TimeStats {
  hoursRemaining: number;
  votingProgress: number;
  peakVotingHours: PeakHour[];
}

export interface PeakHour {
  hour: number;
  voteCount: number;
}

export interface DemographicStats {
  byFaculty: DemographicBreakdown[];
  byYearOfStudy: DemographicBreakdown[];
  byDepartment: DemographicBreakdown[];
}

export interface DemographicBreakdown {
  name: string;
  faculty?: string;
  department?: string;
  year?: number;
  count: number;
  percentage: number;
}

export interface ElectionFilters {
  status?: ElectionStatus;
  type?: ElectionType;
  createdById?: string;
  search?: string;
  startDate?: Date;
  endDate?: Date;
}

export interface ElectionSearchParams {
  filters: ElectionFilters;
  page?: number;
  limit?: number;
  sortBy?: string;
  order?: 'asc' | 'desc';
}

export interface VotingProgress {
  electionId: string;
  totalEligibleVoters: number;
  totalVotesCast: number;
  currentTurnout: number;
  averageVotingTime: number;
  activeVoters: number;
  completedVoters: number;
  hourlyProgress: HourlyProgress[];
}

export interface HourlyProgress {
  hour: string;
  votes: number;
  cumulative: number;
}

export interface ElectionPermission {
  canView: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canStart: boolean;
  canEnd: boolean;
  canPause: boolean;
  canViewStats: boolean;
  canManageVoters: boolean;
  canExport: boolean;
}

export interface ElectionNotification {
  id: string;
  electionId: string;
  type: string;
  scheduledFor: Date;
  sent: boolean;
  sentAt?: Date;
  subject: string;
  template: string;
  data: any;
}