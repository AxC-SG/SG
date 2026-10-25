export type AiArtifactType = 'AI_AGENT' | 'AI_AGENT_VERSION' | 'AI_PROMPT' | 'AI_TOOL' | 'AI_COMPONENT' | 'AI_MODEL' | 'AI_GUARDRAIL' | 'MCP_GATEWAY' | 'MCP_TARGET' | 'MCP_SERVER' | 'KNOWLEDGE_BASE' | 'DATA_SOURCE' | 'DATA_STORE' | 'SEARCH_INDEX' | 'SUPPORTING_RESOURCE' | 'OTHER_AI_ARTIFACT';
export type AiProvider = 'AWS' | 'AZURE' | 'MICROSOFT_COPILOT';

export type AiSecuritySummary = {
  logicalAgentCount?: number;
  artifactCounts: Record<string, number>;
  nativeKindCounts: Record<string, number>;
  providerCounts: Record<string, number>;
  openFindings: number;
  incompleteScopes: number;
  lastCompleteSnapshotAt: string | null;
};

export type AiSeverityGridRow = {
  nativeKind: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

export type AiSeverityGrid = {
  rows: AiSeverityGridRow[];
};

export type AiGridSystem = {
  id: string;
  name: string;
  status: string;
  revision: number;
  memberCount: number;
  updatedAt: string;
};

export type AiGridCoverage = {
  runId: string | null;
  coverageEpochId: string | null;
  authoritativeScopeHeads: number;
  currentArtifacts: number;
  applicablePublished: number;
  required: number;
  tenantEnabled: number;
  preview: number;
  tenantDisabled: number;
  evidenceReady: number;
  evaluatedPass: number;
  evaluatedFail: number;
  noDecision: number;
  notApplicable: number;
  stale: number;
  unsupported: number;
  decisionReachabilityPercent: number;
  ownerFacingDecisionReachabilityPercent: number;
  artifactsFailing: number;
};

export type AiTopRiskArtifact = {
  id: string;
  name: string;
  nativeKind: string;
  provider: string;
  accountId: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  score: number;
};

export type AiGridCoverageDimension = {
  coverageEpochId: string;
  dimension: 'TECHNOLOGY' | 'PROVIDER' | 'FAMILY' | 'ACCOUNT' | 'ENVIRONMENT' | 'OWNER' | 'POLICY' | 'FRAMEWORK' | 'ASSOCIATION';
  value: string;
  expected: number;
  recorded: number;
  missing: number;
  pass: number;
  fail: number;
  noDecision: number;
};

export type AiFrameworkControlCoverage = {
  controlId: string;
  name: string;
  coverageStatus: 'EFFECTIVE' | 'PARTIAL' | 'PREVIEW' | 'NOT_ASSESSED' | 'BREADTH_ONLY' | 'NOT_COVERED';
  mappedPolicies: number;
  distributedPolicies: number;
  selectedPolicies: number;
  previewPolicies: number;
  previewDecisionReadyPolicies: number;
  effectivePolicies: number;
  applicableCount: number;
  decisionReadyCount: number;
  blockers: string[];
  mappings: Array<{
    policyId: string;
    policyVersion: string;
    mappingType: 'DIRECT' | 'PARTIAL' | 'SUPPORTING';
    rationale: string;
    selection: AiGridPolicySelection | null;
    readiness: string | null;
    distributed: boolean;
  }>;
};

export type AiFrameworkCoverage = {
  framework: string;
  frameworkVersion: string;
  coverageEpochId: string | null;
  runId: string | null;
  tenantSchemaReady: boolean;
  blockers: string[];
  controls: AiFrameworkControlCoverage[];
  legacyCompatibility: {
    policies: number;
    distributed: number;
    required: number;
    enabled: number;
    preview: number;
  };
};

export type AiFrameworkDefinition = {
  framework: string;
  frameworkVersion: string;
  displayName: string;
  controls: Array<{ controlId: string; name: string; displayOrder: number }>;
};

export type AiRuntimeTelemetryReadiness = {
  windowStart: string;
  windowEnd: string;
  windowDays: number;
  minimumFillRate: number;
  minimumAgentCorrelationRate: number;
  minimumVersionCorrelationRate: number;
  minimumExecutionsPerProvider: number;
  minimumVersionApplicableExecutions: number;
  available: boolean;
  program2EntryGateMet: boolean;
  blockers: string[];
  providers: Array<{
    sourceId: string;
    provider: string;
    sourceKind: 'PROVIDER_CONNECTOR' | 'TELEMETRY_ADAPTER';
    requiredForProgramGate: boolean;
    configured: boolean;
    evidenceClass?: string | null;
    certificationState?: string | null;
    executions: number;
    consequentialEvents: number;
    approvalStateFillRate: number;
    policyStateFillRate: number;
    actionOutcomeFillRate: number;
    executionApprovalStateFillRate: number;
    executionPolicyStateFillRate: number;
    agentCorrelationRate: number;
    versionCorrelationRate: number;
    versionApplicableExecutions: number;
    averageDeliveryLatencyMs: number;
    acceptedEvents: number;
    duplicateRate: number;
    quarantineRate: number;
    receivedBytes: number;
  quotaAcceptedEvents: number;
  quotaAcceptedBytes: number;
  estimatedStorageCostUsd: number;
    quotaSoftLimit: boolean;
    quotaExhausted: boolean;
    entryGateMet: boolean;
    blockers: string[];
    alerts: string[];
  }>;
};

export type AiGridPolicySelection = 'REQUIRED' | 'ENABLED' | 'PREVIEW' | 'DISABLED';

export type AiGridPolicyAssessmentStateSummary = {
  policyId: string;
  policyVersion: string;
  pass: number;
  fail: number;
  unknown: number;
  notAssessed: number;
};

export type AiGridBulkPolicySelectionResult = {
  distributedPolicies: number;
  changedPolicies: number;
  enabledPolicies: number;
  requiredPolicies: number;
};

export type AiGridPolicy = {
  policyId: string;
  version: string;
  name: string;
  severity: string;
  lifecycle: 'DRAFT' | 'VALIDATED' | 'APPROVED' | 'CANARY' | 'PUBLISHED' | 'DEPRECATED' | 'RETIRED';
  workflowClass: string;
  selection: AiGridPolicySelection;
  controlObjectiveId: string;
  /** Null for legacy catalog policies that predate provider tagging. */
  provider: string | null;
  evaluationMode: string;
  artifactTypesJson: string;
  nativeKindsJson?: string;
  requiredResourceFamiliesJson: string;
  baseEvidenceTiersJson: string;
  conditionalCapabilitiesJson: string;
  requiredCapabilitiesJson: string;
  frameworkMappingsJson: string;
  readiness: 'READY' | 'PARTIAL' | 'BLOCKED' | 'NO_RESOURCES' | 'NOT_APPLICABLE' | 'NOT_EVALUATED';
  failedArtifacts: number;
  totalArtifacts: number;
};

export type AiGridPolicyDistribution = {
  policyId: string;
  available: boolean;
  defaultSelection: AiGridPolicySelection;
  rolloutStage: 'GENERAL_AVAILABILITY' | 'CANARY' | 'DEV' | 'PAUSED' | 'RETIRED';
  canaryTenantIdsJson: string;
  pinnedVersion: string | null;
  updatedBy: string;
  updatedAt: string;
  version: string;
  name: string;
  severity: string;
  lifecycle: 'DRAFT' | 'VALIDATED' | 'APPROVED' | 'CANARY' | 'PUBLISHED' | 'DEPRECATED' | 'RETIRED';
  controlObjectiveId?: string;
  provider?: 'AWS' | 'AZURE' | 'MULTI_CLOUD' | string;
  evaluationMode?: string;
  artifactTypesJson?: string;
  nativeKindsJson?: string;
  baseEvidenceTiersJson?: string;
  conditionalCapabilitiesJson?: string;
  frameworkMappingsJson?: string;
  releaseFamily?: string | null;
  releaseWave?: string | null;
  approvedPackageDigest?: string | null;
  releaseDecisionId?: string | null;
  inactiveReason?: 'PLATFORM_DEPRECATED' | 'TENANT_DISABLED' | null;
};

export type AiGridShippingStatus = {
  expectedPolicies: number;
  installedPolicies: number;
  publishedPolicies: number;
  distributedPolicies: number;
  digestMatchedPolicies: number;
  rolloutPendingTenants: number;
  blockers: string[];
};

export type AiGridPolicyRollout = {
  id: string;
  releaseId: string;
  releaseType: string;
  policyId: string;
  previousVersion: string | null;
  newVersion: string;
  packageDigest: string;
  approvedDigest: string | null;
  releaseDecisionId: string | null;
  status: string;
  createdAt: string;
  completedAt: string | null;
};

export type AiGridPlatformPolicyDetail = {
  policyId: string;
  version: string;
  name: string;
  description: string;
  severity: string;
  lifecycle: 'DRAFT' | 'VALIDATED' | 'APPROVED' | 'CANARY' | 'PUBLISHED' | 'DEPRECATED' | 'RETIRED';
  workflowClass: string;
  defaultSelection: AiGridPolicySelection;
  controlObjectiveId: string;
  objectiveName: string | null;
  securityIntent: string | null;
  remediationIntent: string | null;
  provider: string;
  evaluationMode: string;
  evaluationDefinition: unknown;
  baseEvidenceTiers: unknown;
  conditionalCapabilities: unknown;
  requiredCapabilities: unknown;
  requiredRelationships: unknown;
  requiredResourceFamilies: unknown;
  nativeKinds: unknown;
  requiredFacts: unknown;
  frameworkMappings: unknown;
  certificationParameterProfile: unknown;
  packageDigest: string;
  packageSourceRef: string;
  releaseFamily: string;
  releaseWave: string;
  governanceOwner: string | null;
  governanceStatus: string;
  tenantConfigurable: boolean;
  governanceNotes: string | null;
  approvedBy: string | null;
  approvedAt: string | null;
  publishedAt: string | null;
  evaluationSubject?: string;
  relationshipTypes?: unknown;
  applicabilityNotes?: string | null;
};

export type AiGridPolicyReleaseReadiness = {
  policyId: string;
  version: string;
  lifecycle: string;
  severity: string;
  catalogDigest: string;
  ready: boolean;
  blockers: string[];
  answerKeyRunId: string | null;
  precisionReviewId: string | null;
  latestDecision: string | null;
  latestDecisionReason: string | null;
  latestDecisionAt: string | null;
  latestApprovedDigest: string | null;
  latestApprovalId: string | null;
  latestApprovalRevoked: boolean;
};

export type AiGridPhase1PolicyCertification = {
  policyId: string;
  version: string;
  catalogDigest: string;
  answerKeyReady: boolean;
  precisionReady: boolean;
  releaseReady: boolean;
  blockers: string[];
};

export type AiGridPhase1CertificationReadiness = {
  totalPolicies: number;
  answerKeyReadyPolicies: number;
  precisionReadyPolicies: number;
  releaseReadyPolicies: number;
  pendingPolicies: number;
  policies: AiGridPhase1PolicyCertification[];
};

export type AiGridPhase1CorpusBootstrap = {
  sourceManifestDigest: string;
  policyCount: number;
  environmentsCreated: number;
  casesCreated: number;
};

export type AiGridPhase1CorpusEnvironment = {
  policyId: string;
  policyVersion: string;
  environmentId: string | null;
  lifecycle: string | null;
  caseCount: number;
  certificationBlockers: string[];
};

export type AiGridPhase1CorpusReadiness = {
  sourceManifestDigest: string;
  totalPolicies: number;
  certifiedEnvironments: number;
  draftEnvironments: number;
  missingEnvironments: number;
  blockedEnvironments: number;
  environments: AiGridPhase1CorpusEnvironment[];
};

export type AiGridPhase1CorpusCertification = {
  sourceManifestDigest: string;
  totalPolicies: number;
  environmentsCertified: number;
  environmentsAlreadyCertified: number;
  blockedEnvironments: string[];
};

export type AiGridPhase1PreviewGate = {
  gateKey: string;
  status: 'PENDING' | 'PASSED' | 'FAILED' | string;
  evidenceReference: string | null;
  resultsJson: string;
  recordedBy: string | null;
  recordedAt: string | null;
};

export type AiGridPhase1PreviewStatus = {
  manifestDigest: string;
  totalPolicies: number;
  providerCounts: Record<string, number>;
  defaultSelectionCounts: Record<string, number>;
  state: string;
  internalTenantId: string | null;
  approvedCohort: string[];
  gates: AiGridPhase1PreviewGate[];
  blockers: string[];
};

export type AiGridPhase1PreviewCertificationProfile = {
  sourceManifestDigest: string;
  profileDigest: string;
  posturePolicies: number;
  correlationPolicies: number;
  caseCount: number;
  scenarioCounts: Record<string, number>;
};

export type AiGridPolicyTenantReconciliation = {
  tenantId: string;
  tenantName: string;
  legacySelections: number;
  governedSelections: number;
  unmappedLegacySelections: number;
  unmappedScopes: number;
  unmappedExceptions: number;
  unmappedParameters: number;
  unmappedFindings: number;
  generatedAt: string;
};

export type AiGridPolicyRetirementStatus = {
  legacyFallbackEnabled: boolean;
  eligibleForRetirement: boolean;
  activeTenantCount: number;
  unmappedRecordCount: number;
};

export type AiGridPolicyCandidate = { id: string; title: string; sourceType: string; status: string; technologyId: string | null; rationale: string; riskScore: number; reachScore: number; evidenceMaturity: number; remediationClarity: number; owner: string | null; priorityScore: number };

export type AiGridOwner = {
  artifactId: string;
  ownerName: string;
  ownerState: 'CONFIRMED';
  ownerSource: string;
  confidence: number | null;
  confidenceMethod: string | null;
  confidenceMethodVersion: string | null;
};

export type AiGridRunMetrics = {
  runId: string;
  provider: string | null;
  completedScopeCount: number;
  processingDurationMs: number;
  providerApiCalls: number | null;
  providerCallMeasurementState: string;
  artifactCount: number;
  snapshotManifestCount: number;
  snapshotBytes: number;
  newSnapshotBytes: number;
  retainedSnapshotBytes: number;
  budgetState: string;
  factCount: number;
  assessmentCount: number;
  passCount: number;
  failCount: number;
  noDecisionCount: number;
  openGapCount: number;
  firstInventoryAt: string | null;
  firstDecisionAt: string | null;
  firstFindingAt: string | null;
  firstGapAt: string | null;
};

export type AiAssessmentStatus = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'PARTIAL' | 'FAILED';
export type AiAssessmentProcessing = {
  collectionStatus?: string;
  assessmentStatus?: AiAssessmentStatus;
  assessedSubjects?: number;
  failedPolicies?: number;
  failureSummaries?: Array<{ policyId: string; code: string; summary: string; retryable: boolean }>;
};

export type AiGridPolicyExecutionResult = AiAssessmentProcessing & {
  runId: string;
  requestedPolicies: number;
  evaluatedPolicies: number;
};

export type AiSecurityArtifact = {
  deployment?: AiAgentDeployment | null;
  id: string;
  provider: string;
  providerResourceId: string;
  artifactType: string;
  nativeKind: string;
  name: string;
  accountId: string;
  region: string;
  active: boolean;
  attributes: Record<string, unknown>;
  ownerName: string | null;
  ownerState: 'CONFIRMED' | 'INFERRED' | 'CANDIDATE' | 'UNOWNED';
  ownerSource: string | null;
  ownerConfidence: number | null;
  ownerConfidenceMethod: string | null;
  ownerConfidenceMethodVersion: string | null;
  businessCriticality: string | null;
  environment: string | null;
  firstObservedAt: string;
  lastObservedAt: string;
  piiScanStatus: 'UNKNOWN' | 'NOT_APPLICABLE' | 'NOT_SCANNED' | 'SCANNED_CLEAN' | 'SCANNED_PII_FOUND' | 'LOOKUP_FAILED';
  piiSource: 'AWS_MACIE' | 'AZURE_PURVIEW' | null;
  piiInfoTypes: string[];
  piiFindingCount: number;
  piiLastScannedAt: string | null;
  attachmentState: 'ROOT' | 'ATTACHED' | 'UNATTACHED_REQUIRED' | 'STANDALONE_OPTIONAL';
  systemIds: string[];
};

export type AiArtifactSummary = {
  deployment?: AiAgentDeployment | null;
  id: string;
  name: string;
  nativeKind: string;
  provider: string;
  accountId: string;
  region: string;
  criticalFindings: number;
  highFindings: number;
  totalFindings: number;
  policiesFailed: number;
  policiesTotal: number;
};

export type AiActivityEvidence = {
  factKey: string;
  valueJson: string;
  state: string;
  evidenceReference: string;
  observedAt: string;
  validFrom: string;
  validUntil: string | null;
  confidence: number | null;
  producerId: string;
  expired: boolean;
};

export type AiSecurityPage<T> = {
  items: T[];
  page: number;
  size: number;
  total: number;
};

export type AiSecurityRelationship = {
  id: string;
  relationshipType: string;
  sourceArtifactId: string;
  sourceName: string;
  targetArtifactId: string;
  targetName: string;
  attributes: Record<string, unknown>;
};

export type AiSecurityGraph = {
  nodes: AiSecurityArtifact[];
  edges: AiSecurityRelationship[];
  truncated: boolean;
  runtimeOverlay?: AiRuntimeGraphOverlay;
};

export type AiRuntimeGraphGroup = {
  id: string;
  provider: string;
  source: string;
  agentArtifactId: string | null;
  agentVersionArtifactId: string | null;
  executionCount: number;
  successCount: number;
  failureCount: number;
  unknownCount: number;
  resolvedCount: number;
  unresolvedCount: number;
  notApplicableCount: number;
  firstEvidenceTime: string;
  lastEvidenceTime: string;
};

export type AiRuntimeGraphEdge = {
  id: string;
  relationshipType: 'EXECUTED_AS' | 'PARTICIPATED_IN';
  runtimeGroupId: string;
  artifactId: string;
  participantRole: 'MODEL' | 'TOOL' | 'PROMPT' | 'COMPONENT' | null;
  executionCount: number;
  firstEvidenceTime: string;
  lastEvidenceTime: string;
};

export type AiRuntimeGraphOverlay = {
  status: 'AVAILABLE' | 'UNAVAILABLE';
  diagnostic: string | null;
  windowStart: string;
  windowEnd: string;
  executionCount: number;
  resolvedCount: number;
  unresolvedCount: number;
  notApplicableCount: number;
  groups: AiRuntimeGraphGroup[];
  edges: AiRuntimeGraphEdge[];
  truncated: boolean;
};

export type AiSecurityFinding = {
  id: string;
  displayId: string;
  policyId: string;
  policyVersion: string;
  artifactId: string | null;
  executionId?: string | null;
  subjectType?: 'ARTIFACT' | 'EXPOSURE_PATH' | string;
  findingKind?: 'AI_POSTURE' | 'AI_EXPOSURE';
  exposurePaths?: Array<{ id: string; title: string; state: string; status: string }>;
  artifactName: string;
  evidenceSource?: string | null;
  evidenceClass?: string | null;
  severity: string;
  status: string;
  title: string;
  evidence: Record<string, unknown>;
  reviewDisposition: string;
  firstObservedAt: string;
  lastObservedAt: string;
  resolvedAt: string | null;
  closedReason?: string | null;
};

export type AiSecurityPolicy = {
  id: string;
  version: string;
  name: string;
  severity: string;
  artifactTypes: string[];
  requiredResourceFamilies: string[];
  description: string;
  remediation: string;
  controlMappings: Record<string, string>;
  available: boolean;
  enabled: boolean;
  openFindings: number;
  lifetimeFindings: number;
  lastEvaluatedAt: string | null;
  decisionCoverage: number;
  decisionCoverageThreshold: number;
  decisionCoverageStatus: 'PASS' | 'FAIL' | 'NO_DATA';
  evaluatedArtifacts: number;
  noDecisionCount: number;
  lifecycle: 'DRAFT' | 'VALIDATED' | 'APPROVED' | 'CANARY' | 'PUBLISHED' | 'DEPRECATED' | 'RETIRED';
  inactiveReason?: 'PLATFORM_DEPRECATED' | 'TENANT_DISABLED' | null;
  platformDefaultSelection?: AiGridPolicySelection;
  configurationSource?: 'PLATFORM_DEFAULT' | 'TENANT_OVERRIDE' | string;
  platformOwner?: string | null;
  governanceStatus?: string;
  tenantConfigurable?: boolean;
};

export type PolicyScopeMode = 'ALL' | 'MATCH_RULES' | 'CUSTOM_LIST';

export type PolicyScopeField = 'PROVIDER' | 'REGION' | 'ACCOUNT_ID' | 'ARTIFACT_TYPE' | 'NATIVE_KIND' | 'NAME';

export type PolicyScopeOperator = 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS';

export type PolicyScopeCondition = {
  field: PolicyScopeField | string;
  operator: PolicyScopeOperator | string;
  value: string;
};

export type PolicyScope = {
  mode: PolicyScopeMode;
  conditionLogic: 'AND' | 'OR';
  conditions: PolicyScopeCondition[];
  updatedBy: string | null;
  updatedAt: string | null;
};

export type PolicyExceptionOverride = 'INCLUDED' | 'EXCLUDED';

export type PolicyException = {
  artifactId: string;
  artifactName: string;
  override: PolicyExceptionOverride;
  reason: string | null;
  createdBy: string;
  createdAt: string;
};

export type PolicyParameterValue = {
  key: string;
  label: string;
  type: string;
  options: string[];
  defaultValue: string;
  helpText: string;
  value: string;
};

export type PolicyConfiguration = AiAssessmentProcessing & {
  governance: {
    platformPolicyVersion: string | null;
    platformLifecycle: string | null;
    platformOwner: string | null;
    governanceStatus: string | null;
    tenantConfigurable: boolean;
    platformDefaultSelection: AiGridPolicySelection | null;
    configurationSource: 'PLATFORM_DEFAULT' | 'TENANT_OVERRIDE' | string;
    tenantConfigurationUpdatedAt: string | null;
  };
  scope: PolicyScope;
  exceptions: PolicyException[];
  parameters: PolicyParameterValue[];
  matchedArtifactCount: number;
  totalArtifactCount: number;
};

export type PolicyAssistExplanation = {
  summary: string;
  generatedAt: string;
};

export type AiSecurityRun = AiAssessmentProcessing & {
  id: string;
  status: string;
  recordsFetched: number;
  recordsFailed: number;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
};

export type AiSecurityScopeDiagnostic = {
  code: string;
  message: string;
  retryable: boolean;
  missingPermissions: string[];
  correlationId: string;
};

export type AiSecurityScope = {
  id: string;
  runId: string;
  accountId: string;
  region: string;
  resourceFamily: string;
  scopeKey: string;
  status: 'COMPLETE' | 'PARTIAL' | 'FAILED' | 'UNSUPPORTED';
  acceptedChunks: number;
  expectedChunks: number;
  diagnosticCode: string | null;
  diagnostics: { items?: AiSecurityScopeDiagnostic[] };
  startedAt: string;
  completedAt: string | null;
};

export type AiSecurityConnectorConfig = {
  id: string;
  accountId: string;
  roleArn: string | null;
  authMode: 'WORKLOAD_IDENTITY' | 'CROSS_ACCOUNT_ROLE';
  externalId?: string | null;
  regions: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityConnectionTest = {
  success: boolean;
  code: string | null;
  message: string;
  retryable: boolean;
  missingPermissions: string[];
  identity: AiSecurityAwsIdentity | null;
  preflight: AiSecurityAwsPreflight | null;
};

export type AiSecurityAwsIdentity = {
  accountId: string;
  arn: string;
  principalId: string;
};

export type AiSecurityAwsActionVerification = {
  action: string;
  status: 'VERIFIED_ALLOWED' | 'VERIFIED_EMPTY' | 'NOT_VERIFIED_EMPTY' | 'UNAUTHORIZED' | 'UNSUPPORTED_API' | 'ERROR' | 'DISABLED';
  detail: string;
};

export type AiSecurityAwsFamilyPreflight = {
  resourceFamily: string;
  region: string;
  status: 'COMPLETE' | 'DISABLED' | 'UNAUTHORIZED' | 'UNSUPPORTED_API' | 'PARTIAL' | 'ERROR';
  actions: AiSecurityAwsActionVerification[];
  customerRemediation: string;
};

export type AiSecurityAwsPreflight = {
  identity: AiSecurityAwsIdentity | null;
  resourceFamilies: AiSecurityAwsFamilyPreflight[];
  providerApiCalls: number;
  explicitlyRequested: boolean;
};

export type AiSecurityAwsFamilyRequirement = {
  resourceFamily: string;
  scope: 'REGIONAL' | 'GLOBAL';
  requiredActions: string[];
  optionalEnrichmentActions: string[];
  verificationProbe: string;
  capabilities: string[];
  policies: string[];
  customerRemediation: string;
};

export type AiSecurityAwsRequirements = {
  matrixVersion: number;
  provider: 'AWS';
  resourceFamilies: AiSecurityAwsFamilyRequirement[];
  prohibitedMutationActions: string[];
};

export type AiSecurityAzureCredentialProfile = {
  id: string;
  name: string;
  authType: 'CLIENT_SECRET' | 'MANAGED_IDENTITY' | 'WORKLOAD_FEDERATION';
  azureTenantId: string;
  clientId: string | null;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  expiresAt: string | null;
  lastVerifiedAt: string | null;
  lastVerificationStatus: string | null;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityAzureConnector = {
  id: string;
  subscriptionId: string;
  azureTenantId: string;
  credentialProfileId: string;
  sourceConfigId: string;
  sourceTargetId: string;
  regions: string[];
  resourceFamilies: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AiSecurityAzureFoundryConfig = {
  configured: boolean;
  azureTenantId: string | null;
  clientId: string | null;
  hasCredential: boolean;
  primarySubscriptionId: string | null;
  subscriptionIds: string[];
  regions: string[];
  foundryEndpointUrl: string | null;
  connectorId: string | null;
  credentialExpiresAt: string | null;
};

/** Metadata-only runtime records. Provider execution identifiers are intentionally absent. */
export type AiAgentExecution = {
  id: string;
  provider: string;
  agentArtifactId: string | null;
  agentVersionArtifactId: string | null;
  correlationStatus: 'RESOLVED' | 'UNRESOLVED' | 'NOT_APPLICABLE';
  correlationDiagnostic: string | null;
  source: string;
  startedAt: string | null;
  completedAt: string | null;
  status: string;
  outcomeCategory: string | null;
  approvalState: string | null;
  policyState: string | null;
  classification: string | null;
  apiVersion: string | null;
  tokenCount: number | null;
  latencyMs: number | null;
  retryCount: number | null;
  spendMicros: number | null;
  evidenceTime: string;
  environmentDigest?: string | null;
  deploymentDigest?: string | null;
  actingIdentityDigest?: string | null;
  delegatedIdentityDigest?: string | null;
  terminationReason?: string | null;
  evidenceSource?: string | null;
  evidenceClass?: string | null;
  evidenceConfidence?: number | null;
  stepCount?: number | null;
  spendCurrency?: string | null;
  spendUnit?: string | null;
  collectedAt?: string | null;
  providerEventTime?: string | null;
  deliveryLatencyMs?: number | null;
};

export type AiAgentExecutionPage = { items: AiAgentExecution[]; page: number; size: number; total: number };
export type AiAgentExecutionEvent = {
  id: string; executionId: string; sequence: number; eventTime: string; eventType: string;
  status: string | null; classification: string | null; evidenceTime: string;
  ingestedAt?: string; actionCategory?: string | null; targetClass?: string | null;
  toolDigest?: string | null; toolVersionDigest?: string | null; targetDigest?: string | null;
  actionCorrelationDigest?: string | null; dataSensitivity?: string | null; dataOperation?: string | null;
  approvalState?: string | null; policyState?: string | null; decisionReason?: string | null;
  enforcementPoint?: string | null; actionOutcome?: string | null; evidenceClass?: string | null;
};

export type CopilotStudioConnector = {
  id: string; organizationUrl: string; credentialProfileId: string; discoveryEnabled: boolean;
  executionEnabled: boolean; killSwitch: boolean; scheduleCron: string; allowedDataverseHosts: string[];
  createdAt: string; updatedAt: string;
};

export type AiSecurityConnectorFeatureFlag = {
  featureKey: string; enabled: boolean; killSwitch: boolean; updatedBy: string | null; updatedAt: string | null;
};

export type AiSecurityAzureFamilyPermission = {
  resourceFamily: string;
  required: string[];
  granted: string[];
  missing: string[];
  status: string;
};

export type AiSecurityAzureConnectionTest = {
  success: boolean;
  code: string | null;
  message: string;
  retryable: boolean;
  correlationId: string;
  resourceFamilies: AiSecurityAzureFamilyPermission[];
};

export type AiSecurityAzureRequirements = {
  matrixVersion: number;
  provider: 'AZURE';
  resourceFamilies: Array<{
    resourceFamily: string;
    apiVersion: string;
    role: string;
    actions: string[];
  }>;
  policies: Array<{
    policyId: string;
    version: string;
    resourceFamilies: string[];
    facts: string[];
    scopes: string[];
    connectorTest: string;
  }>;
  prohibitedActions: string[];
  roleTemplate: {
    name: string;
    isCustom: boolean;
    description: string;
    actions: string[];
    notActions: string[];
    dataActions: string[];
    notDataActions: string[];
    assignableScopes: string[];
  };
};

export type AiGridExposureSummary = {
  id: string;
  correlationId: string;
  correlationVersion: string;
  title: string;
  severity: string;
  state: 'EXPOSURE_HYPOTHESIS' | 'VALIDATED_EXPOSURE' | 'CLOSED';
  status: 'OPEN' | 'CLOSED';
  confidence: number;
  rootCauseArtifactId: string;
  firstObservedAt: string;
  lastObservedAt: string;
  findingId: string | null;
  affectedSystems: number;
  impact: string;
  rootCause: string;
  breakpoint: string;
  confidenceMethod: string;
};

export type AiGridExposurePage = { items: AiGridExposureSummary[]; nextCursor: string | null };

export type AiExposurePriority = {
  id: string; title: string; severity: string; priority: number;
  severityPoints: number; confidencePoints: number; publicExposurePoints: number;
  criticalityPoints: number; recencyPoints: number; activityPoints: number; confidence: number;
  rootCauseArtifactId: string; breakpoint: string; owner: string; provider: string;
  accountId: string; lastObservedAt: string;
};

export type AiOverviewActivity = {
  eventType: 'DISCOVERED' | 'VALIDATED'; subjectType: 'ARTIFACT' | 'EXPOSURE'; subjectId: string;
  name: string; provider: string; accountId: string; observedAt: string;
};

export type AiExposureIntelligenceOverview = {
  systemCount: number; assetCount: number; validatedExposureCount: number; criticalHighExposureCount: number;
  incompleteScopeCount: number; unsupportedScopeCount: number; authoritativeAt: string | null;
  topPriorities: AiExposurePriority[]; recentActivity: AiOverviewActivity[];
};

export type AiActionQueueItem = {
  id: string; kind: 'VALIDATED_EXPOSURE' | 'POLICY_FINDING'; title: string; severity: string;
  priority: number; owner: string; provider: string; accountId: string; remediation: string;
  confidence: number | null; lastObservedAt: string;
};

export type AiAssetPosture = {
  artifactId: string;
  controls: Array<{ policyId: string; selection: string; evidenceReadiness: string; decision: string; missingEvidenceJson: string }>;
  exposures: AiExposurePriority[];
};

export type AiGridExposureDetail = {
  exposure: AiGridExposureSummary;
  observations: Array<{
    id: string; runId: string; state: string; entryArtifactId: string | null; systemId: string | null;
    pathJson: string; evidenceJson: string; validFrom: string;
    validUntil: string | null; confidence: number; observedAt: string;
  }>;
  associations: Array<{ systemId: string | null; artifactId: string | null; role: string }>;
};

export type AiAgentDeploymentReason = 'VERIFIED_SERVING_ROUTE' | 'NO_ALIAS_ROUTE' | 'NO_SERVING_ENDPOINT'
  | 'NO_ACTIVE_DEPLOYMENT' | 'ZERO_TRAFFIC_ALLOCATION' | 'NOT_PUBLISHED' | 'NO_ENABLED_CHANNEL' | 'NO_SERVING_ROUTE'
  | 'NO_EVIDENCE' | 'STALE_EVIDENCE' | 'INCOMPLETE_SCOPE' | 'PERMISSION_DENIED' | 'UNSUPPORTED_API'
  | 'UNSUPPORTED_CHANNEL_EVIDENCE' | 'COLLECTION_DISABLED' | 'BUDGET_EXHAUSTED' | 'PROVIDER_ERROR'
  | 'UNRESOLVED_IDENTITY' | 'UNRESOLVED_VERSION' | 'AMBIGUOUS_ROUTE_STATE';

export type AiAgentDeployment = {
  status: 'SERVED' | 'NOT_CURRENTLY_SERVED' | 'UNVERIFIED';
  reasonCode: AiAgentDeploymentReason;
  observedAt: string | null;
  expiresAt: string | null;
  evidenceReferences: Array<{ family: string; scopeId: string; runId: string; observedAt: string; collectionStatus: string; reasonCode: AiAgentDeploymentReason; routeIds: string[] }>;
  lastVerifiedObservation: { status: string; reasonCode: AiAgentDeploymentReason; observedAt: string; expiresAt: string } | null;
};
