/** Tenant CBOM visibility contracts (backend CbomVisibilityDtos, CbomSemanticDiffService, CbomReportService). */

export type CbomOverview = {
  observedAt: string;
  risk: {
    openCritical: number; openHigh: number; openMedium: number; openLow: number;
    averagePostureScore: number | null; assetsWithCriticalOrHigh: number; productionAssetsWithCriticalOrHigh: number;
  };
  assurance: {
    activeArtifacts: number; assessedArtifacts: number; assessmentCoverage: number | null;
    averageConfidence: number | null; averageCompleteness: number | null; claimsByAssurance: Record<string, number>;
  };
  remediation: {
    open: number; overdue: number; slaCompliance: number | null; suppressed: number;
    suppressionsExpiringIn30Days: number; resolvedLast30Days: number;
  };
  rotation: { expired: number; expiringIn30Days: number; expiringIn60Days: number; expiringIn90Days: number };
  pqc: { quantumVulnerableFindings: number; quantumVulnerableComponents: number };
  productionAssetsAtRisk: Array<{ assetId: string; name: string; environment: string | null; critical: number; high: number }>;
  componentsByType: Record<string, number>;
  cryptoExposureNote: string;
};

export type CbomTrendPoint = {
  date: string; live: boolean; activeComponents: number; activeArtifacts: number; assessedArtifacts: number;
  openCritical: number; openHigh: number; openMedium: number; openLow: number; quantumVulnerable: number;
  averageRiskScore: number | null; averageConfidence: number | null; averageCompleteness: number | null;
  openCryptoFindings: number; overdueCryptoFindings: number; suppressedCryptoFindings: number;
};

export type CbomTrends = { days: number; points: CbomTrendPoint[] };

export type CbomInventoryItem = {
  id: string; name: string; assetType: string; primitive: string | null; keySize: number | null; curve: string | null;
  protocolVersion: string | null; storageLocation: string | null; notAfter: string | null; riskScore: number | null;
  assetId: string | null; assetName: string | null; environment: string | null; sourceBomId: string;
  sourceDocument: string | null; openFindings: number; highestSeverity: string | null; evidenceState: string | null;
};

export type CbomInventoryPage = {
  items: CbomInventoryItem[]; page: number; size: number; total: number; totalCapped: boolean; hasNext: boolean;
};

export type CbomInventoryFilters = {
  assetType?: string; primitive?: string; severity?: string; evidenceState?: string; custody?: string;
  environment?: string; q?: string; bomId?: string;
};

export type CbomComponentDetail = {
  component: CbomInventoryItem;
  properties: Record<string, string | number | boolean | null>;
  provenance: {
    bomId: string; documentName: string | null; serialNumber: string | null; checksumSha256: string | null;
    sourceType: string | null; sourceMethod: string | null; sourceLabel: string | null; bomStatus: string | null;
    ingestedAt: string | null; assessmentRunId: string | null; rulePackage: string | null; rulePackageDigest: string | null;
    evaluatorVersion: string | null; assessedAt: string | null;
  } | null;
  claims: Array<{ claimPath: string; assuranceLevel: string; evidenceState: string; explanation: string }>;
  findings: Array<{
    id: string; ruleId: string; ruleVersion: string | null; severity: string; riskClass: string; title: string;
    detail: string | null; evidence: string | null; recommendation: string | null; status: string; evidenceState: string;
    firstSeenAt: string | null; lastSeenAt: string | null;
    canonical: { id: string; displayId: string; status: string; assignedTo: string | null; dueAt: string | null; suppressedUntil: string | null } | null;
  }>;
  relationships: Array<{ direction: string; relationshipType: string; otherType: string; otherId: string; otherName: string | null; evidenceKind: string }>;
};

export type CbomFieldChange = { field: string; category: string; before: string | null; after: string | null };

export type CbomSemanticDiff = {
  bomId: string; baselineBomId: string | null; baselineSource: 'PREDECESSOR' | 'REQUESTED' | 'NONE'; currentStatus: string;
  componentSummary: Record<string, number>; findingSummary: Record<string, number>;
  componentChanges: Array<{
    changeType: 'ADDED' | 'NOT_OBSERVED' | 'CHANGED'; identity: string; name: string; assetType: string | null;
    baselineComponentId: string | null; currentComponentId: string | null; fields: CbomFieldChange[];
    riskBefore: number | null; riskAfter: number | null;
  }>;
  assuranceChanges: Array<{ identity: string; claim: string; before: string; after: string; direction: string }>;
  findingOutcomes: Array<{
    outcome: string; identity: string | null; componentName: string; ruleId: string; title: string;
    severityBefore: string | null; severityAfter: string | null; baselineFindingId: string | null;
    currentFindingId: string | null; canonicalStatus: string | null;
  }>;
  ambiguous: Array<{ identity: string; baselineMatches: number; currentMatches: number }>;
  posture: { openBefore: number; openAfter: number; riskBefore: number | null; riskAfter: number | null };
};

export type CbomReportStatus = 'QUEUED' | 'GENERATING' | 'READY' | 'FAILED' | 'EXPIRED';

export type CbomReport = {
  id: string; bomId: string; assessmentRunId: string; format: 'JSON' | 'HTML'; status: CbomReportStatus;
  regeneratedFrom: string | null; requestedBy: string; schemaVersion: string | null; checksumSha256: string | null;
  filename: string | null; sizeBytes: number | null; errorMessage: string | null; createdAt: string;
  completedAt: string | null; expiresAt: string | null; downloadCount: number; lastDownloadedAt: string | null;
  signatureStatus: 'UNSIGNED';
};

export type FindingTicketAttempt = {
  id: string; provider: string | null; template: 'CRYPTO' | 'DEFAULT'; outcome: 'SUCCEEDED' | 'FAILED';
  ticketKey: string | null; errorMessage: string | null; attemptedBy: string; attemptedAt: string;
};

export type CryptoQueueItem = {
  findingId: string; displayId: string; title: string; severity: string | null; status: string; assignedTo: string | null;
  ownerGroup: string | null; dueAt: string | null; workflowSubstate: string | null; verificationStatus: string | null;
  targetState: string | null; verificationRequestedAt: string | null; overdue: boolean;
};

export type CryptoRemediationQueue = {
  observedAt: string; verificationQueue: CryptoQueueItem[]; overdue: CryptoQueueItem[];
  slaBySeverity: Array<{ severity: string; open: number; overdue: number; dueWithin7Days: number; unassigned: number }>;
};

export type CryptoEffectiveness = {
  days: number; from: string; to: string; opened: number; closed: number; verifiedClosures: number; reopened: number;
  verificationsAccepted: number; verificationsRejected: number; verificationAcceptanceRate: number | null;
  closuresByReason: Record<string, number>;
  bySeverity: Array<{ severity: string; closed: number; meanDaysToClose: number | null; closedWithinSla: number | null }>;
};

export type CampaignFinding = {
  findingId: string; displayId: string; title: string; findingKind: string; severity: string | null; status: string;
  assignedTo: string | null; ownerGroup: string | null; dueAt: string | null; verificationStatus: string | null; addedAt: string;
};

export type CbomGraphNode = {
  type: string; id: string; distance: number; label: string | null; kind: string | null; openFindings: number; highestSeverity: string | null;
};
export type CbomGraphEdge = {
  id: string; sourceType: string; sourceId: string; targetType: string; targetId: string; relationshipType: string;
  evidenceKind: string; confidence: number | null; evidenceSummary: string | null; validUntil: string | null; stale: boolean;
};
export type CbomBlastRadius = {
  componentId: string;
  graph: { nodes: CbomGraphNode[]; edges: CbomGraphEdge[]; truncated: boolean; depth: number };
  applications: Array<{ assetId: string; name: string | null; environment: string | null; distance: number }>;
  affectedComponents: number; openFindings: number; openFindingsBySeverity: Record<string, number>;
};
export type CbomContradiction = {
  id: string; assetId: string | null; assetName: string | null; identity: string; claim: string;
  componentAId: string; documentA: string | null; valueA: string | null; componentBId: string; documentB: string | null; valueB: string | null;
  status: 'OPEN' | 'ACCEPTED_A' | 'ACCEPTED_B' | 'DISMISSED' | 'OBSOLETE'; detectedAt: string; reviewedBy: string | null;
  reviewedAt: string | null; reviewNote: string | null; version: number;
};

export type CbomGatePolicy = {
  environment: string; failOnSeverities: string[]; minimumCompleteness: number; blockOnInvalid: boolean;
  updatedBy: string; updatedAt: string | null; version: number; configured: boolean;
};
export type CbomPqcProgress = {
  openQuantumVulnerable: number; inCampaigns: number; notInCampaign: number;
  campaigns: Array<{ campaignId: string; name: string; status: string; dueAt: string | null; createdBy: string; findings: number;
    open: number; resolved: number; overdue: number; percentComplete: number | null; owners: string[] }>;
};
export type CbomPortfolio = {
  groupBy: string;
  groups: Array<{ group: string; assets: number; components: number; openCritical: number; openHigh: number; openMedium: number;
    openLow: number; quantumVulnerable: number; openCryptoFindings: number; overdueCryptoFindings: number; averagePostureScore: number | null }>;
};
