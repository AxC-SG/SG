export type OccurrenceKind = 'inventory-components' | 'cbom-components';

export type OccurrenceAssignmentPreview = {
  subjectId: string;
  currentTeamId: string | null;
  currentStatus: string | null;
  directFindings: number;
  wouldChange: boolean;
  blockedByDirectClaim: boolean;
  conflict: boolean;
  alreadyEffective: boolean;
  affectedFindings: number;
};

export type OccurrenceAssignmentRequest = { teamId: string; reason: string; expiresAt?: string | null };
