export type RiskPolicy = {
  criticalThreshold: number;
  highThreshold: number;
  criticalSlaDays: number;
  highSlaDays: number;
  mediumSlaDays: number;
  lowSlaDays: number;
  assetCriticalSlaMultiplier: number;
  assetHighSlaMultiplier: number;
  assetMediumSlaMultiplier: number;
  assetLowSlaMultiplier: number;
  autoCloseEnabled: boolean;
  autoCloseAssetIdentifier?: string;
  autoCloseAfterDays: number;
  autoCloseRequiredConsecutiveMisses: number;
  autoCloseNotObservedEnabled: boolean;
  autoCloseComponentRemovedEnabled: boolean;
  autoCloseAssetRetiredEnabled: boolean;
  autoCloseSourceDisabledEnabled: boolean;
  autoCloseDuplicateEnabled: boolean;
  autoCloseRunIntervalDays: number;
  autoCloseLastRunAt?: string;
  findingGenerationMode: 'AUTO' | 'MANUAL';
  findingsScoreConfig?: string;
  // Triage urgency signal weights — control how findings/CVEs are ranked
  // before investigation starts. All weights 0–2; 0 = disabled, 2 = highest influence.
  triageExploitabilityWeight: number;
  triageBlastRadiusWeight: number;
  triageEolRiskWeight: number;
  triageSlaBreachWeight: number;
  triageMissingOwnerBoost: number;
  triagePatchGapBoost: number;
};


export type SuppressionRuleState = 'DRAFT' | 'APPROVED' | 'IN_REVIEW' | 'REJECTED' | 'EXPIRED';
export type SuppressionRuleRecordType = 'CVE' | 'FINDING';

export type SuppressionCondition = {
  table: string;
  column: string;
  operator: string;
  value: string;
};

export type SuppressionRule = {
  id: string;
  name: string;
  state: SuppressionRuleState;
  recordType: SuppressionRuleRecordType;
  conditionsJson: string;
  conditionLogic: 'AND' | 'OR';
  reason?: string;
  validFrom?: string;
  validTo?: string;
  createdAt: string;
  updatedAt: string;
  suppressedCount: number;
};

export type SuppressionRuleRequest = {
  name: string;
  state: SuppressionRuleState;
  recordType: SuppressionRuleRecordType;
  conditionsJson: string;
  conditionLogic: 'AND' | 'OR';
  reason?: string;
  validFrom?: string;
  validTo?: string;
};

export type OwnershipRuleResponse = {
  id: string;
  name: string;
  condition: string;
  userGroup: string;
  executionOrder: number;
  matchedCount: number;
  createdAt: string;
  updatedAt: string;
};

export type OwnershipRuleRequest = {
  name: string;
  condition: string;
  userGroup: string;
  executionOrder?: number;
};
