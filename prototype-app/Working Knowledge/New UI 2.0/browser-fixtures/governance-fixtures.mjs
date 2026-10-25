// Deterministic Governance and platform administration fixtures for UI 2.0 visual/behaviour
// review (P5).
//
// Shapes follow frontend/src/features/ai-security/types.ts (tenant policies, framework coverage,
// platform policy distribution), features/admin/types.ts and the Tenant / PlatformUser /
// DemoRequest / AllowedTenant / TenantSupportGrant / EOL types in api/client.ts and
// features/eol/types.ts. All names, subjects, digests and counts are synthetic. Tenant policy IDs
// reuse the AI Findings fixture policy IDs so AI Findings and policy detail stay consistent.
// Writes return canned results and nothing is persisted. Not authenticated evidence.
import { aiFindings } from './findings-fixtures.mjs';

const BASE = Date.parse('2026-10-24T12:00:00Z');
const day = 86_400_000;
const iso = (offsetDays) => new Date(BASE + offsetDays * day).toISOString();

export const FIXTURE_TENANT_ID = '00000000-0000-0000-0000-000000000001';
export const PRIMARY_POLICY_ID = 'policy.aws.2';
export const PRIMARY_PLATFORM_POLICY_ID = 'aws.bedrock.agent-tool-scope';
export const APPROVED_PLATFORM_POLICY_ID = 'azure.foundry.content-filter-blocking';
export const ACTIVE_TENANT_ID = '00000000-0000-0000-0000-0000000000a1';
export const SUSPENDED_TENANT_ID = '00000000-0000-0000-0000-0000000000a5';
export const TAKEN_SLUG = 'taken-slug';
export const PENDING_GRANT_ID = 'grant-pending-initech';

/** Platform owner before entering a tenant (platformScope). */
export const platformActor = {
  creator: true,
  principal: 'fixture.owner@example.test',
  userId: 'fixture-owner',
  tenantId: null,
  tenantName: null,
  roles: ['PLATFORM_OWNER'],
  allowedTenants: [],
  platformScope: true,
  actingAsPlatformOwner: false,
  entitlements: {},
};

const ok = (json) => ({ status: 200, json });
const noContent = { status: 204, body: '' };
const notFound = { status: 404, json: { message: 'Not found (fixture)' } };
const conflict = (message) => ({ status: 409, json: { message } });

// ── Frameworks and tenant policies ──────────────────────────────────────────
const FRAMEWORKS = [
  { framework: 'OWASP_LLM_TOP_10', frameworkVersion: '2025', displayName: 'OWASP Top 10 for LLM Applications 2025', controls: [
    ['LLM01', 'Prompt injection'], ['LLM02', 'Sensitive information disclosure'], ['LLM06', 'Excessive agency'], ['LLM10', 'Unbounded consumption'],
  ] },
  { framework: 'OWASP_AGENTIC_TOP_10', frameworkVersion: '2026', displayName: 'OWASP Agentic Security Top 10', controls: [
    ['ASI02', 'Tool misuse'], ['ASI03', 'Identity and privilege abuse'], ['ASI06', 'Memory and context poisoning'],
  ] },
].map((framework) => ({ ...framework, controls: framework.controls.map(([controlId, name], index) => ({ controlId, name, displayOrder: index + 1 })) }));

const mapping = (framework, controlId, mappingType = 'DIRECT') => ({ framework, frameworkVersion: framework === 'OWASP_LLM_TOP_10' ? '2025' : '2026', controlId, mappingType });

// Extra tenant policies beyond the five AI Findings policies:
// [policyId, name, severity, provider, selection, readiness, failed, total, artifactTypes, families, conditional, mappings]
const EXTRA_POLICIES = [
  ['policy.multi_cloud.6', 'Agent identity is explicitly configured', 'MEDIUM', 'MULTI_CLOUD', 'REQUIRED', 'READY', 0, 14, ['AI_AGENT'], [], [], [mapping('OWASP_AGENTIC_TOP_10', 'ASI03')]],
  ['policy.azure.7', 'Diagnostic logging is enabled for AI accounts', 'LOW', 'AZURE', 'DISABLED', 'BLOCKED', 0, 0, [], ['AZURE_DIAGNOSTIC_SETTINGS'], ['DIAGNOSTIC_SETTINGS'], [mapping('OWASP_LLM_TOP_10', 'LLM10', 'SUPPORTING')]],
  ['policy.aws.8', 'Knowledge base data sources restrict cross-account reads', 'HIGH', 'AWS', 'PREVIEW', 'NO_RESOURCES', 0, 0, ['KNOWLEDGE_BASE'], [], [], [mapping('OWASP_LLM_TOP_10', 'LLM02', 'PARTIAL')]],
];

const FINDING_POLICY_META = {
  1: ['ENABLED', 'READY', 3, 18, ['AI_GUARDRAIL'], [mapping('OWASP_LLM_TOP_10', 'LLM01')]],
  2: ['REQUIRED', 'PARTIAL', 4, 11, ['AI_MODEL', 'AI_AGENT'], [mapping('OWASP_LLM_TOP_10', 'LLM02'), mapping('OWASP_AGENTIC_TOP_10', 'ASI03', 'PARTIAL')]],
  3: ['ENABLED', 'READY', 1, 9, ['AI_AGENT', 'KNOWLEDGE_BASE'], [mapping('OWASP_AGENTIC_TOP_10', 'ASI02'), mapping('OWASP_LLM_TOP_10', 'LLM06')]],
  4: ['DISABLED', 'NOT_EVALUATED', 0, 0, ['AI_AGENT'], [mapping('OWASP_AGENTIC_TOP_10', 'ASI03')]],
  5: ['ENABLED', 'READY', 0, 6, ['OTHER_AI_ARTIFACT'], [mapping('OWASP_LLM_TOP_10', 'LLM10', 'SUPPORTING')]],
};

const tenantPolicies = [
  ...aiFindings.map((finding, index) => {
    const [selection, readiness, failedArtifacts, totalArtifacts, artifactTypes, mappings] = FINDING_POLICY_META[index + 1];
    const provider = finding.evidenceSource === 'MICROSOFT_COPILOT' ? 'AZURE' : finding.evidenceSource;
    return { policyId: finding.policyId, name: finding.title, severity: finding.severity, provider, selection, readiness, failedArtifacts, totalArtifacts,
      artifactTypes, families: [], conditional: index === 1 ? ['FOUNDRY_DEPLOYMENTS_RAI'] : [], mappings };
  }),
  ...EXTRA_POLICIES.map(([policyId, name, severity, provider, selection, readiness, failedArtifacts, totalArtifacts, artifactTypes, families, conditional, mappings]) => (
    { policyId, name, severity, provider, selection, readiness, failedArtifacts, totalArtifacts, artifactTypes, families, conditional, mappings })),
];

const gridPolicy = (policy, selection = policy.selection) => ({
  policyId: policy.policyId, version: '1.0.0', name: policy.name, severity: policy.severity, lifecycle: 'PUBLISHED', workflowClass: 'POSTURE',
  selection, controlObjectiveId: `objective.${policy.policyId}`, provider: policy.provider, evaluationMode: 'STATIC_FACTS',
  artifactTypesJson: JSON.stringify(policy.artifactTypes), nativeKindsJson: JSON.stringify(policy.artifactTypes.length ? ['BEDROCK_AGENT'] : []),
  requiredResourceFamiliesJson: JSON.stringify(policy.families), baseEvidenceTiersJson: '["CONFIGURATION"]',
  conditionalCapabilitiesJson: JSON.stringify(policy.conditional), requiredCapabilitiesJson: '[]', frameworkMappingsJson: JSON.stringify(policy.mappings),
  readiness: policy.readiness, failedArtifacts: policy.failedArtifacts, totalArtifacts: policy.totalArtifacts,
});

const policyDetail = (policy, selection) => ({
  id: policy.policyId, version: '1.0.0', name: policy.name, severity: policy.severity, artifactTypes: policy.artifactTypes.length ? policy.artifactTypes : ['MODEL'],
  requiredResourceFamilies: policy.families, description: `${policy.name} (fixture policy). Evaluated from static provider configuration facts.`,
  remediation: 'Restrict access to approved principals and re-run the assessment.',
  controlMappings: Object.fromEntries(policy.mappings.map((item) => [item.controlId, item.framework])),
  available: true, enabled: selection !== 'DISABLED', openFindings: aiFindings.some((finding) => finding.policyId === policy.policyId) ? 1 : 0, lifetimeFindings: 3,
  lastEvaluatedAt: iso(0), decisionCoverage: policy.readiness === 'READY' ? 0.96 : 0.62, decisionCoverageThreshold: 0.9,
  decisionCoverageStatus: policy.readiness === 'READY' ? 'PASS' : 'FAIL', evaluatedArtifacts: policy.totalArtifacts, noDecisionCount: 1, lifecycle: 'PUBLISHED',
  inactiveReason: selection === 'DISABLED' ? 'TENANT_DISABLED' : null, platformDefaultSelection: 'ENABLED',
  configurationSource: selection === policy.selection ? 'PLATFORM_DEFAULT' : 'TENANT_OVERRIDE', platformOwner: 'Platform Security', governanceStatus: 'APPROVED', tenantConfigurable: true,
});

const policyConfiguration = (policy, selection) => ({
  assessmentStatus: 'COMPLETE', assessedSubjects: policy.totalArtifacts, failedPolicies: 0,
  governance: { platformPolicyVersion: '1.0.0', platformLifecycle: 'PUBLISHED', platformOwner: 'Platform Security', governanceStatus: 'APPROVED', tenantConfigurable: true,
    platformDefaultSelection: 'ENABLED', configurationSource: selection === policy.selection ? 'PLATFORM_DEFAULT' : 'TENANT_OVERRIDE', tenantConfigurationUpdatedAt: iso(-4) },
  scope: { mode: 'MATCH_RULES', conditionLogic: 'AND', conditions: [{ field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: 'AI_AGENT' }, { field: 'PROVIDER', operator: 'EQUALS', value: policy.provider }],
    updatedBy: 'fixture.admin@example.test', updatedAt: iso(-4) },
  exceptions: [{ artifactId: 'artifact-sandbox', artifactName: 'sandbox-evaluation-agent', override: 'EXCLUDED', reason: 'Isolated sandbox without customer data.', createdBy: 'fixture.admin@example.test', createdAt: iso(-9) }],
  parameters: [
    { key: 'allowedPrincipals', label: 'Allowed principals', type: 'STRING', options: [], defaultValue: '', helpText: 'Comma-separated principal ARNs or object IDs.', value: 'arn:aws:iam::111122223333:role/claims-ops' },
    { key: 'enforcementMode', label: 'Enforcement mode', type: 'ENUM', options: ['AUDIT', 'BLOCK'], defaultValue: 'AUDIT', helpText: 'Audit records findings only.', value: 'AUDIT' },
  ],
  matchedArtifactCount: Math.max(policy.totalArtifacts - 1, 0), totalArtifactCount: policy.totalArtifacts,
});

const COVERAGE_STATUS = ['EFFECTIVE', 'PARTIAL', 'NOT_ASSESSED', 'BREADTH_ONLY', 'NOT_COVERED'];
const coverageFor = (frameworkKey, version) => {
  const framework = FRAMEWORKS.find((item) => item.framework === frameworkKey && item.frameworkVersion === version);
  if (!framework) return null;
  return {
    framework: frameworkKey, frameworkVersion: version, coverageEpochId: `epoch-${frameworkKey.toLowerCase()}`, runId: 'run-fixture-0007', tenantSchemaReady: true, blockers: [],
    controls: framework.controls.map((control, index) => {
      const mapped = tenantPolicies.filter((policy) => policy.mappings.some((item) => item.controlId === control.controlId));
      const coverageStatus = COVERAGE_STATUS[(index + (frameworkKey === 'OWASP_LLM_TOP_10' ? 0 : 1)) % COVERAGE_STATUS.length];
      return {
        controlId: control.controlId, name: control.name, coverageStatus, mappedPolicies: mapped.length, distributedPolicies: mapped.length,
        selectedPolicies: mapped.filter((policy) => policy.selection !== 'DISABLED').length, previewPolicies: mapped.filter((policy) => policy.selection === 'PREVIEW').length,
        previewDecisionReadyPolicies: 0, effectivePolicies: coverageStatus === 'EFFECTIVE' ? mapped.length : 0, applicableCount: mapped.reduce((sum, policy) => sum + policy.totalArtifacts, 0),
        decisionReadyCount: coverageStatus === 'EFFECTIVE' ? mapped.reduce((sum, policy) => sum + policy.totalArtifacts, 0) : 0,
        blockers: coverageStatus === 'PARTIAL' ? ['capability:DIAGNOSTIC_SETTINGS:MISSING'] : coverageStatus === 'NOT_ASSESSED' ? ['NO_COVERAGE_EPOCH'] : coverageStatus === 'NOT_COVERED' ? ['POLICY_NOT_DISTRIBUTED'] : [],
        mappings: mapped.map((policy) => ({ policyId: policy.policyId, policyVersion: '1.0.0', mappingType: 'DIRECT', rationale: 'Fixture mapping.', selection: policy.selection, readiness: policy.readiness, distributed: true })),
      };
    }),
    legacyCompatibility: { policies: tenantPolicies.length, distributed: tenantPolicies.length, required: 2, enabled: 4, preview: 1 },
  };
};

const assessmentStates = tenantPolicies.filter((policy) => policy.totalArtifacts > 0).map((policy) => ({
  policyId: policy.policyId, policyVersion: '1.0.0', pass: policy.totalArtifacts - policy.failedArtifacts - (policy.readiness === 'PARTIAL' ? 2 : 0),
  fail: policy.failedArtifacts, unknown: policy.readiness === 'PARTIAL' ? 2 : 0, notAssessed: 0,
}));

// ── Platform policy distribution ────────────────────────────────────────────
// [policyId, name, severity, provider, lifecycle, rolloutStage, defaultSelection, available, mappings, artifactTypes]
const PLATFORM_POLICY_ROWS = [
  [PRIMARY_PLATFORM_POLICY_ID, 'Unrestricted agent tool permissions', 'CRITICAL', 'AWS', 'VALIDATED', 'DEV', 'ENABLED', true, [mapping('OWASP_AGENTIC_TOP_10', 'ASI02'), mapping('OWASP_LLM_TOP_10', 'LLM06', 'PARTIAL')], ['AI_AGENT', 'MCP_TARGET']],
  [APPROVED_PLATFORM_POLICY_ID, 'Content filters run in blocking mode', 'HIGH', 'AZURE', 'APPROVED', 'CANARY', 'REQUIRED', true, [mapping('OWASP_LLM_TOP_10', 'LLM01')], ['AI_GUARDRAIL']],
  ['multi.agent-identity-configured', 'Agent identity is explicitly configured', 'MEDIUM', 'MULTI_CLOUD', 'PUBLISHED', 'GENERAL_AVAILABILITY', 'REQUIRED', true, [mapping('OWASP_AGENTIC_TOP_10', 'ASI03')], ['AI_AGENT']],
  ['aws.bedrock.model-endpoint-public', 'Model endpoint allows public access', 'CRITICAL', 'AWS', 'PUBLISHED', 'GENERAL_AVAILABILITY', 'ENABLED', true, [mapping('OWASP_LLM_TOP_10', 'LLM02')], ['AI_MODEL']],
  ['azure.ml.diagnostic-logging', 'Diagnostic logging is enabled for AI accounts', 'LOW', 'AZURE', 'PUBLISHED', 'PAUSED', 'PREVIEW', true, [mapping('OWASP_LLM_TOP_10', 'LLM10', 'INFORMATIVE')], ['OTHER_AI_ARTIFACT']],
  ['aws.kb.cross-account-read', 'Knowledge base data sources restrict cross-account reads', 'HIGH', 'AWS', 'DEPRECATED', 'RETIRED', 'DISABLED', false, [mapping('OWASP_LLM_TOP_10', 'LLM02', 'PARTIAL')], ['KNOWLEDGE_BASE']],
];

const DIGEST = (index) => `sha256:${'4f1c9a7e2b3d5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8'.slice(index, 64)}${'0'.repeat(index)}`;

const platformPolicies = PLATFORM_POLICY_ROWS.map(([policyId, name, severity, provider, lifecycle, rolloutStage, defaultSelection, available, mappings, artifactTypes], index) => ({
  policyId, available, defaultSelection, rolloutStage, canaryTenantIdsJson: rolloutStage === 'CANARY' ? JSON.stringify([ACTIVE_TENANT_ID]) : '[]', pinnedVersion: null,
  updatedBy: 'fixture.owner@example.test', updatedAt: iso(-index - 1), version: `1.${index}.0`, name, severity, lifecycle, controlObjectiveId: `objective.${policyId}`,
  provider, evaluationMode: 'STATIC_FACTS', artifactTypesJson: JSON.stringify(artifactTypes), nativeKindsJson: JSON.stringify(provider === 'AZURE' ? ['FOUNDRY_RAI_POLICY'] : ['BEDROCK_AGENT']),
  baseEvidenceTiersJson: '["CONFIGURATION"]', conditionalCapabilitiesJson: '[]', frameworkMappingsJson: JSON.stringify(mappings), releaseFamily: 'phase-1', releaseWave: index < 2 ? 'wave-2' : 'wave-1',
  approvedPackageDigest: ['APPROVED', 'PUBLISHED'].includes(lifecycle) ? DIGEST(index) : null, releaseDecisionId: ['APPROVED', 'PUBLISHED'].includes(lifecycle) ? `decision-${index + 1}` : null,
  inactiveReason: lifecycle === 'DEPRECATED' ? 'PLATFORM_DEPRECATED' : null,
}));

const platformPolicyDetail = (policy) => ({
  policyId: policy.policyId, version: policy.version, name: policy.name, severity: policy.severity, lifecycle: policy.lifecycle, workflowClass: 'POSTURE',
  description: `${policy.name}. Identifies configurations that fail this control from static provider facts (fixture).`, defaultSelection: policy.defaultSelection,
  controlObjectiveId: policy.controlObjectiveId, objectiveName: policy.name, securityIntent: `Prevent ${policy.name.toLowerCase()} from exposing tenant AI workloads.`,
  remediationIntent: 'Constrain the configuration to the approved scope, then re-run the tenant assessment.', provider: policy.provider, evaluationMode: 'STATIC_FACTS',
  evaluationDefinition: { all: [{ fact: 'toolScope', operator: 'NOT_EQUALS', value: '*' }] }, baseEvidenceTiers: ['CONFIGURATION'], conditionalCapabilities: [], requiredCapabilities: [],
  requiredRelationships: [], requiredResourceFamilies: [], nativeKinds: JSON.parse(policy.nativeKindsJson), requiredFacts: ['toolScope'], frameworkMappings: JSON.parse(policy.frameworkMappingsJson),
  certificationParameterProfile: null, packageDigest: DIGEST(1), packageSourceRef: `catalog/phase-1/${policy.policyId}@${policy.version}`, releaseFamily: 'phase-1', releaseWave: policy.releaseWave,
  governanceOwner: 'Platform Security', governanceStatus: policy.lifecycle === 'VALIDATED' ? 'AWAITING_APPROVAL' : 'APPROVED', tenantConfigurable: policy.lifecycle !== 'DEPRECATED',
  governanceNotes: null, approvedBy: policy.approvedPackageDigest ? 'fixture.owner@example.test' : null, approvedAt: policy.approvedPackageDigest ? iso(-6) : null,
  publishedAt: policy.lifecycle === 'PUBLISHED' ? iso(-5) : null, evaluationSubject: 'ARTIFACT', relationshipTypes: [], applicabilityNotes: null,
});

const rollouts = [
  { id: 'rollout-1', releaseId: 'release-phase-1-w2', releaseType: 'CANARY', policyId: APPROVED_PLATFORM_POLICY_ID, previousVersion: '1.0.0', newVersion: '1.1.0', packageDigest: DIGEST(1), approvedDigest: DIGEST(1), releaseDecisionId: 'decision-2', status: 'FAILED', createdAt: iso(-1), completedAt: null },
  { id: 'rollout-2', releaseId: 'release-phase-1-w1', releaseType: 'GENERAL_AVAILABILITY', policyId: 'multi.agent-identity-configured', previousVersion: null, newVersion: '1.2.0', packageDigest: DIGEST(2), approvedDigest: DIGEST(2), releaseDecisionId: 'decision-3', status: 'COMPLETED', createdAt: iso(-5), completedAt: iso(-5) },
];

// ── Tenants, platform users, audit, demo requests ───────────────────────────
// [id, name, slug, status, planCode, demoOwnerEmail, demoExpiresOffset, demoDataStatus, createdOffset]
const TENANT_ROWS = [
  [ACTIVE_TENANT_ID, 'Acme Corporation', 'acme', 'ACTIVE', 'ENTERPRISE', null, null, 'NOT_REQUESTED', -220],
  ['00000000-0000-0000-0000-0000000000a2', 'Initech Demo', 'initech-demo', 'ACTIVE', 'DEMO', 'demo.owner@initech.example.test', 28, 'SEEDED', -9],
  ['00000000-0000-0000-0000-0000000000a3', 'Umbrella Research', 'umbrella-research', 'PROVISIONING', 'STANDARD', null, null, 'NOT_REQUESTED', -0.1],
  ['00000000-0000-0000-0000-0000000000a4', 'Wayne Logistics', 'wayne-logistics', 'PROVISIONING_FAILED', 'STANDARD', null, null, 'NOT_REQUESTED', -1],
  [SUSPENDED_TENANT_ID, 'Globex Industries with a deliberately long workspace display name', 'globex-industries-with-a-deliberately-long-slug', 'SUSPENDED', 'ENTERPRISE', null, null, 'NOT_REQUESTED', -400],
];

const tenants = TENANT_ROWS.map(([id, name, slug, status, planCode, demoOwnerEmail, demoExpires, demoDataStatus, created]) => ({
  id, name, slug, status, planCode, billingRef: `BILL-${slug.slice(0, 8).toUpperCase()}`, maxConnectorCount: 25, maxServiceAccountCount: 10, maxDailySbomUploads: 200,
  maxExportRows: 50000, maxDailyExposureRefreshes: planCode === 'DEMO' ? 4 : 24, demoExpiresAt: demoExpires == null ? null : iso(demoExpires),
  demoCreatedBy: demoOwnerEmail ? 'fixture.owner@example.test' : null, demoSource: demoOwnerEmail ? 'DEMO_REQUEST' : null, demoOwnerEmail,
  demoDataRequested: demoDataStatus !== 'NOT_REQUESTED', demoDataStatus, demoDataVersion: demoDataStatus === 'SEEDED' ? '2026.10' : null, createdAt: iso(created), updatedAt: iso(created + 0.5),
}));

const schemaStatus = {
  items: tenants.map((tenant, index) => ({
    tenantId: tenant.id, tenantName: tenant.name, tenantStatus: tenant.status, schemaName: `tenant_${tenant.slug.replace(/-/g, '_').slice(0, 24)}`,
    currentVersion: tenant.status === 'PROVISIONING_FAILED' ? 41 : 47, targetVersion: 47, status: tenant.status === 'PROVISIONING_FAILED' ? 'FAILED' : 'CURRENT',
    structuralChecksum: 'c0ffee12', lastSuccessfulVersion: tenant.status === 'PROVISIONING_FAILED' ? 41 : 47,
    failureCode: tenant.status === 'PROVISIONING_FAILED' ? 'MIGRATION_V42_FAILED' : null,
    failureMessage: tenant.status === 'PROVISIONING_FAILED' ? 'Migration V42 failed: relation "ai_policy_scope" already exists.' : null,
    migrationStartedAt: iso(-1), migrationCompletedAt: tenant.status === 'PROVISIONING_FAILED' ? null : iso(-1), updatedAt: iso(-1), migrationRunId: `run${index}a7f2c9e1b4d8`,
  })),
  page: 0, size: 200, total: tenants.length,
};

const connectorHealth = [
  { tenantId: ACTIVE_TENANT_ID, tenantName: 'Acme Corporation', connectorKey: 'aws-inspector', enabled: true, autoSyncEnabled: true, lastTestStatus: 'SUCCESS', lastTestMessage: null, lastTestedAt: iso(-0.5), lastSyncAt: iso(-0.2), healthState: 'HEALTHY' },
];

const platformUsers = [
  ['pu-1', 'fixture.owner@example.test', 'Fixture Owner', 'ACTIVE', ['PLATFORM_OWNER'], true, false, -0.01],
  ['pu-2', 'second.owner@example.test', 'Second Owner', 'ACTIVE', ['PLATFORM_OWNER'], true, false, -3],
  ['pu-3', 'new.operator@example.test', null, 'INVITED', ['PLATFORM_OWNER'], false, true, null],
].map(([userId, email, displayName, status, globalRoles, passwordSet, setupPending, lastSeen], index) => ({
  userId, externalSubject: `auth0|${userId}`, email, displayName, status, globalRoles, passwordSet, setupPending, passwordSetAt: passwordSet ? iso(-60 + index) : null,
  lastSetupIssuedAt: setupPending ? iso(-0.5) : null, lastSetupCompletedAt: passwordSet ? iso(-60 + index) : null, lastSeenAt: lastSeen == null ? null : iso(lastSeen), createdAt: iso(-90 + index * 30),
}));

const auditEvent = (id, offset, action, actorSubject, actorRole, targetType, targetId, outcome = 'SUCCESS', details = null, tenantId = null) => ({
  id, occurredAt: iso(offset), tenantId, actorSubject, actorRole, action, targetType, targetId, outcome, detailsJson: details ? JSON.stringify(details) : null,
});

const platformAudit = [
  auditEvent('pa-1', -0.5, 'PLATFORM_USER_SETUP_LINK_ISSUED', 'fixture.owner@example.test', 'PLATFORM_OWNER', 'PLATFORM_USER', 'pu-3'),
  auditEvent('pa-2', -3, 'PLATFORM_USER_ROLE_GRANTED', 'fixture.owner@example.test', 'PLATFORM_OWNER', 'PLATFORM_USER', 'pu-2', 'SUCCESS', { role: 'PLATFORM_OWNER' }),
  auditEvent('pa-3', -4, 'PLATFORM_USER_LOGIN_FAILED', 'unknown@example.test', null, 'PLATFORM_USER', null, 'DENIED'),
];

const demoRequests = [
  ['dr-1', 'ops.lead@hooli.example.test', 'Jordan Rivera', 'Hooli', 'PENDING', null],
  ['dr-2', 'ciso@initech.example.test', 'Sam Okafor', 'Initech', 'APPROVED', '00000000-0000-0000-0000-0000000000a2'],
  ['dr-3', 'student@example.test', 'Alex Kim', 'Self', 'REJECTED', null],
].map(([id, email, fullName, company, status, tenantId], index) => ({
  id, email, fullName, company, roleTitle: index === 0 ? 'Head of Security Operations' : null, companySize: '201-1000', useCase: 'AI workload posture across AWS and Azure.',
  notes: null, status, requestedAt: iso(-2 - index * 3), decidedAt: status === 'PENDING' ? null : iso(-1 - index * 3), decidedBy: status === 'PENDING' ? null : 'fixture.owner@example.test',
  rejectionReason: status === 'REJECTED' ? 'Not a business evaluation.' : null, bootstrapStatus: status === 'APPROVED' ? 'COMPLETED' : null, tenantId, provisionedPlanCode: tenantId ? 'DEMO' : null,
  latestInvite: tenantId ? { id: 'invite-dr-2', requestId: id, tenantId, tenantName: 'Initech Demo', email, status: 'SENT', expiresAt: iso(6), acceptedAt: null, lastSentAt: iso(-4), inviteUrl: 'https://app.example.test/invite/fixture' } : null,
}));

// ── Authorized workspaces and support grants ────────────────────────────────
const authorizedWorkspaces = [
  { id: 'playground-tenant', name: 'Playground', slug: 'open-playground', role: 'TENANT_ADMIN', accessMode: 'DIRECT_PLAYGROUND_MEMBERSHIP', accessReferenceId: 'membership-playground', expiresAt: null, revocable: false },
  { id: ACTIVE_TENANT_ID, name: 'Acme Corporation', slug: 'acme', role: 'SECURITY_ANALYST', accessMode: 'SUPPORT_READ_ONLY', accessReferenceId: 'grant-acme', expiresAt: iso(2), revocable: true },
];

const supportGrants = [
  { id: PENDING_GRANT_ID, tenantId: '00000000-0000-0000-0000-0000000000a2', tenantName: 'Initech Demo', invitedPlatformSubject: 'auth0|pu-1', reason: 'Investigate connector sync failure reported in ticket SUP-4821.',
    scope: null, accessMode: 'WRITE_ENABLED', status: 'PENDING', grantedBySubject: 'admin@initech.example.test', acceptedBySubject: null, revokedBySubject: null, requestedAt: iso(-0.3), acceptedAt: null, expiresAt: iso(1), revokedAt: null },
];

// ── Tenant administration ───────────────────────────────────────────────────
const members = [
  ['m-1', 'fixture.analyst@example.test', 'Fixture Analyst', 'TENANT_ADMIN', 'ACTIVE'],
  ['m-2', 'priya.nair@example.test', 'Priya Nair', 'SECURITY_ANALYST', 'ACTIVE'],
  ['m-3', 'li.wei@example.test', 'Li Wei', 'SECURITY_ANALYST', 'ACTIVE'],
  ['m-4', 'auditor@example.test', null, 'READ_ONLY_AUDITOR', 'ACTIVE'],
  ['m-5', 'former.employee@example.test', 'Former Employee', 'VIEWER', 'DISABLED'],
].map(([id, email, displayName, role, status], index) => ({ id, userId: `user-${id}`, subject: `auth0|${id}`, email, displayName, role, status, createdAt: iso(-120 + index * 10) }));

const invites = [
  { id: 'inv-1', tenantId: FIXTURE_TENANT_ID, email: 'new.hire@example.test', displayName: 'New Hire', subject: 'email|new.hire@example.test', role: 'SECURITY_ANALYST', status: 'PENDING',
    createdAt: iso(-1), expiresAt: iso(6), acceptedAt: null, lastSentAt: iso(-1), invitedBySubject: 'auth0|m-1', invitedByDisplayName: 'Fixture Analyst', deliveryDetail: null },
  { id: 'inv-2', tenantId: FIXTURE_TENANT_ID, email: 'contractor@partner.example.test', displayName: null, subject: 'email|contractor@partner.example.test', role: 'VIEWER', status: 'PENDING',
    createdAt: iso(-8), expiresAt: iso(-1), acceptedAt: null, lastSentAt: iso(-8), invitedBySubject: 'auth0|m-1', invitedByDisplayName: 'Fixture Analyst', deliveryDetail: 'Email delivery is not connected; share the invite link directly.' },
];

const serviceAccounts = [
  { id: 'sa-1', tenantId: FIXTURE_TENANT_ID, name: 'github-sbom-ingest', keyId: 'key-7f2a91', role: 'INVENTORY_ADMIN', status: 'ACTIVE', createdAt: iso(-40), lastUsedAt: iso(-0.1) },
  { id: 'sa-2', tenantId: FIXTURE_TENANT_ID, name: 'legacy-ci-uploader', keyId: 'key-0b33c4', role: 'VIEWER', status: 'INACTIVE', createdAt: iso(-300), lastUsedAt: iso(-120) },
];

const tenantAudit = [
  auditEvent('ae-1', -0.2, 'TENANT_MEMBER_ROLE_UPDATED', 'auth0|m-1', 'TENANT_ADMIN', 'TENANT_MEMBER', 'm-3', 'SUCCESS', { from: 'VIEWER', to: 'SECURITY_ANALYST' }, FIXTURE_TENANT_ID),
  auditEvent('ae-2', -1, 'TENANT_INVITE_CREATED', 'auth0|m-1', 'TENANT_ADMIN', 'TENANT_INVITE', 'inv-1', 'SUCCESS', null, FIXTURE_TENANT_ID),
  auditEvent('ae-3', -2, 'SERVICE_ACCOUNT_DEACTIVATED', 'auth0|m-1', 'TENANT_ADMIN', 'SERVICE_ACCOUNT', 'sa-2', 'SUCCESS', null, FIXTURE_TENANT_ID),
  auditEvent('ae-4', -3, 'AI_POLICY_SELECTION_UPDATED', 'auth0|m-2', 'SECURITY_ANALYST', 'AI_POLICY', PRIMARY_POLICY_ID, 'DENIED', null, FIXTURE_TENANT_ID),
];

// ── Platform EOL console ────────────────────────────────────────────────────
// [packageName, ecosystem, slug, cycle, eolOffsetDays, assetCount]
const EOL_PACKAGES = [
  ['log4j-core', 'maven', 'log4j', '2.14', -900, 7], ['python', 'generic', 'python', '3.7', -850, 12], ['nodejs', 'generic', 'nodejs', '16', -400, 9],
  ['openssl', 'generic', 'openssl', '1.1.1', -390, 21], ['spring-boot', 'maven', 'spring-boot', '2.7', -240, 5], ['django', 'pypi', 'django', '4.1', -300, 3],
  ['postgresql', 'generic', 'postgresql', '12', 25, 4], ['kubernetes', 'generic', 'kubernetes', '1.29', 60, 6], ['ubuntu', 'generic', 'ubuntu', '20.04', 150, 18],
  ['react', 'npm', 'react', '18', 400, 11], ['jquery', 'npm', null, null, null, 2],
];
const eolPackages = EOL_PACKAGES.map(([packageName, ecosystem, eolSlug, eolCycle, eolOffset, assetCount]) => ({
  packageName, ecosystem, eolSlug: eolSlug ?? undefined, eolCycle: eolCycle ?? undefined, eolDate: eolOffset == null ? undefined : iso(eolOffset).slice(0, 10),
  isEol: eolOffset == null ? undefined : eolOffset < 0, eolDaysRemaining: eolOffset == null ? undefined : eolOffset, assetCount,
}));
const eolProducts = ['log4j', 'python', 'nodejs', 'openssl', 'spring-boot', 'django', 'postgresql', 'kubernetes', 'ubuntu', 'react'].map((slug, index) => ({
  slug, displayName: slug.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()), cpeVendor: slug === 'log4j' ? 'apache' : slug, cpeProduct: slug,
  purlType: ['log4j', 'spring-boot'].includes(slug) ? 'maven' : slug === 'react' ? 'npm' : undefined, aliases: slug === 'nodejs' ? ['node', 'node.js'] : [],
  releaseCount: 8 + index, lastModified: iso(-10 - index), lastFetchedAt: iso(-0.4),
}));

const springPage = (items, params, defaultSize = 50) => {
  const size = Number(params.get('size') ?? defaultSize);
  const page = Number(params.get('page') ?? 0);
  return { content: items.slice(page * size, page * size + size), number: page, size, totalElements: items.length, totalPages: Math.max(1, Math.ceil(items.length / size)) };
};

/** Returns a Playwright fulfil object for governance/admin requests, or undefined. */
export function governanceFixtureFor(rawUrl, method = 'GET', body = null) {
  const url = new URL(rawUrl);
  const path = url.pathname.replace(/^\/api/, '');
  const params = url.searchParams;
  const segment = (index) => decodeURIComponent(path.split('/')[index] ?? '');
  const json = (() => { try { return body ? JSON.parse(body) : {}; } catch { return {}; } })();

  // Tenant policies and framework coverage
  if (path === '/ai-policies') return ok(tenantPolicies.map((policy) => gridPolicy(policy)));
  const tenantPolicy = path.startsWith('/ai-policies/') ? tenantPolicies.find((policy) => policy.policyId === segment(2)) : undefined;
  if (path.startsWith('/ai-policies/') && !tenantPolicy) return notFound;
  if (tenantPolicy) {
    const rest = path.split('/').slice(3).join('/');
    if (rest === 'selection' && method === 'PUT') return ok(tenantPolicies.map((policy) => gridPolicy(policy, policy === tenantPolicy ? json.selection : policy.selection)));
    if (rest === '') return ok(policyDetail(tenantPolicy, tenantPolicy.selection));
    if (['configuration', 'scope', 'parameters'].includes(rest) || rest.startsWith('exceptions')) return ok(policyConfiguration(tenantPolicy, tenantPolicy.selection));
    if (rest === 'assist/explain') return ok({ summary: 'Fixture explanation: this policy checks static configuration facts only.', generatedAt: iso(0) });
    return notFound;
  }
  if (path === '/ai-frameworks') return ok(FRAMEWORKS);
  if (path === '/ai-framework-coverage') {
    const coverage = coverageFor(params.get('framework'), params.get('version'));
    return coverage ? ok(coverage) : notFound;
  }
  if (path === '/ai-assessment-states/latest') return ok(assessmentStates);
  if (path === '/ai-assessments/execute' && method === 'POST') {
    return ok({ runId: 'run-fixture-0008', assessmentStatus: 'COMPLETE', assessedSubjects: 24, failedPolicies: 0, failureSummaries: [] });
  }
  if (path.startsWith('/ai-assessments/')) return ok({ assessmentStatus: 'COMPLETE', assessedSubjects: 24, failedPolicies: 0 });

  // Platform policy distribution
  if (path === '/platform/ai-grid/policies') {
    const lifecycle = params.get('lifecycle');
    return ok(platformPolicies.filter((policy) => !lifecycle || policy.lifecycle === lifecycle));
  }
  if (path === '/platform/ai-grid/policies/shipping-status') {
    return ok({ expectedPolicies: 6, installedPolicies: 6, publishedPolicies: 3, distributedPolicies: 5, digestMatchedPolicies: 5, rolloutPendingTenants: 1, blockers: ['aws.kb.cross-account-read: digest mismatch against approved package'] });
  }
  const versionMatch = path.match(/^\/platform\/ai-grid\/policies\/([^/]+)\/versions\/([^/]+)$/);
  if (versionMatch) {
    const policy = platformPolicies.find((candidate) => candidate.policyId === decodeURIComponent(versionMatch[1]));
    return policy ? ok(platformPolicyDetail(policy)) : notFound;
  }
  if (path === '/platform/ai-grid/policy-rollouts') return ok(rollouts);
  if (/^\/platform\/ai-grid\/policy-rollouts\/[^/]+\/retry$/.test(path) && method === 'POST') return noContent;
  const validation = path.match(/^\/platform\/ai-grid\/validation\/policies\/([^/]+)\/(approve|dev-deploy|publish|deprecate|release-readiness)$/);
  if (validation) {
    if (validation[2] === 'approve') return ok({ approved: true });
    if (validation[2] === 'release-readiness') return ok({ ready: true, blockers: [] });
    return ok({ accepted: true });
  }

  // Tenants and tenant lifecycle
  if (path === '/tenants') return ok(tenants);
  if (path === '/platform/tenant-schema-status') return ok(schemaStatus);
  if (path === '/platform/inventory-connectors/health') return ok(connectorHealth);
  if (path === '/platform/tenants' && method === 'POST') {
    if (json.slug === TAKEN_SLUG) return conflict(`Tenant slug "${TAKEN_SLUG}" is already in use.`);
    return ok({ ...tenants[2], id: '00000000-0000-0000-0000-0000000000b1', name: json.name, slug: json.slug, status: 'PROVISIONING', createdAt: iso(0) });
  }
  const tenantAction = path.match(/^\/platform\/tenants\/([^/]+)\/(status|demo-expiry|provisioning-retry|owner-recovery|demo-data)$/);
  if (tenantAction) {
    const tenant = tenants.find((candidate) => candidate.id === decodeURIComponent(tenantAction[1]));
    if (!tenant) return notFound;
    if (tenantAction[2] === 'status') return ok({ ...tenant, status: json.status });
    if (tenantAction[2] === 'demo-expiry') return ok({ ...tenant, demoExpiresAt: json.expiresAt });
    return ok(tenant);
  }

  // Platform users, audit, demo requests
  if (path === '/platform/users') return method === 'POST' ? ok({ ...platformUsers[2], email: json.email ?? platformUsers[2].email }) : ok(platformUsers);
  if (/^\/platform\/users\/[^/]+\/setup-link$/.test(path) && method === 'POST') {
    // Same-origin: the console opens setupUrl in the current tab (window.open(..., '_self')).
    return ok({ userId: segment(3), email: 'new.operator@example.test', setupUrl: '/setup/fixture-platform-user-token' });
  }
  if (/^\/platform\/users\/[^/]+\/roles\/[^/]+$/.test(path) && method === 'DELETE') return noContent;
  if (path === '/audit-events/platform-users') return ok(platformAudit);
  if (path === '/platform/demo-requests') return ok(demoRequests);
  const demoAction = path.match(/^\/platform\/demo-requests\/([^/]+)(?:\/(approve|reject|resend-invite|issue-setup-link))?$/);
  if (demoAction) {
    const request = demoRequests.find((candidate) => candidate.id === demoAction[1]);
    if (!request) return notFound;
    if (method === 'DELETE') return noContent;
    if (demoAction[2] === 'approve') return ok({ ...request, status: 'APPROVED' });
    if (demoAction[2] === 'reject') return ok({ ...request, status: 'REJECTED', rejectionReason: json.reason ?? '' });
    if (demoAction[2] === 'issue-setup-link') {
      return ok({ requestId: request.id, inviteId: 'invite-dr-2', tenantId: request.tenantId, tenantName: 'Initech Demo', email: request.email, inviteStatus: 'SENT', inviteExpiresAt: iso(6), inviteUrl: '/invite/fixture-demo-token', setupUrl: '/setup/fixture-demo-token' });
    }
    if (demoAction[2] === 'resend-invite') return ok(request.latestInvite);
    return ok(request);
  }

  // Authorized workspaces
  if (path === '/auth/authorized-workspaces') return ok(authorizedWorkspaces);
  if (path === '/auth/support-grants') return ok(supportGrants);
  if (/^\/auth\/support-grants\/[^/]+\/accept$/.test(path) && method === 'POST') return ok({ ...supportGrants[0], status: 'ACCEPTED', acceptedAt: iso(0) });
  if (path === '/auth/tenant-context' && (method === 'POST' || method === 'DELETE')) {
    return ok({ token: 'fixture-workspace-token', tokenType: 'Bearer', expiresAt: iso(0.5) });
  }

  // Tenant administration
  const tenantScoped = path.match(/^\/tenants\/([^/]+)\/(members|invites)(?:\/([^/]+))?(?:\/(resend|bulk))?$/);
  if (tenantScoped) {
    const [, , collection, id, action] = tenantScoped;
    if (collection === 'members') {
      if (!id) return method === 'POST' ? ok(members[1]) : ok(members);
      const member = members.find((candidate) => candidate.id === id);
      if (!member) return notFound;
      return method === 'DELETE' ? noContent : ok({ ...member, ...json });
    }
    if (id === 'bulk' || action === 'bulk') {
      const rows = json.invites ?? [];
      return ok({ requestedCount: rows.length, invitedCount: rows.length, failedCount: 0, results: rows.map((row, index) => ({ email: row.email, status: 'INVITED', inviteId: `inv-bulk-${index}` })) });
    }
    if (!id) return method === 'POST' ? ok({ ...invites[0], id: 'inv-new', email: json.email, displayName: json.displayName ?? null, role: json.role ?? 'VIEWER', createdAt: iso(0) }) : ok(invites);
    const invite = invites.find((candidate) => candidate.id === id);
    if (!invite) return notFound;
    return method === 'DELETE' ? noContent : ok({ ...invite, lastSentAt: iso(0) });
  }
  if (path === '/service-accounts') return method === 'POST' ? ok({ ...serviceAccounts[0], id: 'sa-new', name: json.name, keyId: json.keyId, role: json.role ?? 'VIEWER', createdAt: iso(0), lastUsedAt: null }) : ok(serviceAccounts);
  const serviceAccount = path.match(/^\/service-accounts\/([^/]+)(?:\/(deactivate|reactivate))?$/);
  if (serviceAccount) {
    const account = serviceAccounts.find((candidate) => candidate.id === serviceAccount[1]);
    if (!account) return notFound;
    if (method === 'DELETE') return noContent;
    return ok({ ...account, status: serviceAccount[2] === 'deactivate' ? 'INACTIVE' : 'ACTIVE' });
  }
  if (path === '/audit-events') return ok(tenantAudit);
  if (path === '/audit-events/export') {
    return { status: 200, headers: { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="fixture-audit-events.csv"' }, body: 'id,occurredAt,action\nae-1,2026-10-24,TENANT_MEMBER_ROLE_UPDATED\n' };
  }

  // Platform EOL console (summary is answered by the inventory fixtures)
  if (path === '/eol/status/packages') {
    const filter = params.get('filter');
    const narrowed = eolPackages.filter((item) => !filter || filter === 'all'
      || (filter === 'eol' && item.isEol === true) || (filter === 'near-eol' && item.isEol === false && (item.eolDaysRemaining ?? 999) <= 180)
      || (filter === 'unknown' && item.isEol === undefined));
    return ok(springPage(narrowed, params));
  }
  if (path === '/eol/status/packages/assets') {
    const item = eolPackages.find((candidate) => candidate.packageName === params.get('packageName'));
    const assets = Array.from({ length: item?.assetCount ?? 0 }, (_, index) => ({ assetName: `${['prod-api-gw', 'billing-core', 'etl-worker'][index % 3]}-${String(index + 1).padStart(2, '0')}`, versions: item?.eolCycle ? `${item.eolCycle}.${index}` : '1.0.0' }));
    return ok(springPage(assets, params, 20));
  }
  if (path === '/eol/products') return ok(eolProducts);
  if (/^\/eol\/products\/[^/]+\/releases$/.test(path)) return ok([]);
  if (path.startsWith('/eol/admin/refresh/') && method === 'POST') return ok({ runId: 'sync-run-fixture-eol', status: 'QUEUED', message: 'EOL refresh queued (fixture).' });

  return undefined;
}
