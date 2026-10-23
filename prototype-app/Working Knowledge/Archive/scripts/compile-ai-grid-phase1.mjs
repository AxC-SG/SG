import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
const appRoot = join(repositoryRoot, 'prototype-app');
const packageRoot = join(appRoot, 'policy-packages', 'agcf');
const manifestPath = join(packageRoot, 'phase-1-manifest.json');
const runtimeManifestPath = join(appRoot, 'backend', 'src', 'main', 'resources', 'ai-grid', 'phase-1-manifest.json');
const capabilityGuidePath = join(appRoot, 'docs', 'ai-grid-phase-1-capability-guide.md');
const frameworkStatementPath = join(appRoot, 'docs', 'ai-grid-phase-1-framework-statement.md');
const changelogPath = join(appRoot, 'docs', 'ai-grid-phase-1-changelog.md');
const seedMigrationPath = join(appRoot, 'backend', 'src', 'main', 'resources', 'db', 'migration', 'postgres_reset', 'V1__platform_schema.sql');
const correctionMigrationPath = seedMigrationPath;
const completionMigrationPath = seedMigrationPath;
const shippingMigrationPath = seedMigrationPath;
const write = process.argv.includes('--write');
const frameworkVersions = {
  CSA_AICM: '1.1',
  OWASP_GENAI_LLM_TOP_10: '2026',
};
const registeredCapabilities = new Set([
  'BEDROCK_AGENTS', 'BEDROCK_GUARDRAILS', 'BEDROCK_KNOWLEDGE_BASES', 'BEDROCK_MODELS_JOBS',
  'BEDROCK_INVOCATION_LOGGING', 'IAM_ROLE_POLICIES', 'LAMBDA_URLS', 'AGENTCORE_GATEWAYS_TARGETS',
  'SAGEMAKER_DOMAINS_MODELS_ENDPOINTS', 'MACIE_CLASSIFICATION', 'AI_ACCOUNTS', 'DIAGNOSTIC_SETTINGS',
  'FOUNDRY_DEPLOYMENTS_RAI', 'FOUNDRY_AGENTS_TOOLS', 'ML_WORKSPACES_ENDPOINTS', 'SEARCH_CONTROL_PLANE',
  'BOT_CONFIGURATION', 'RBAC_ASSIGNMENTS', 'PURVIEW_CLASSIFICATION',
  'FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE', 'MULTI_CLOUD_GRAPH',
]);
const registeredRelationships = new Set(['DIRECT_PROVIDER_RELATIONSHIP']);
const correlationReferences = new Map([
  ['AGCF-XSP-001', ['R2_EXTERNAL_SENSITIVE_ACCESS', '2.0.0']],
  ['AGCF-XSP-002', ['R2_UNTRUSTED_AUTONOMOUS_EXECUTION', '2.0.0']],
  ['AGCF-XSP-003', ['R2_EXCESSIVE_TOOL_PRIVILEGE', '2.0.0']],
  ['AGCF-XSP-004', ['R2_EXTERNAL_MCP_SENSITIVE_ACCESS', '2.0.0']],
  ['AGCF-XSP-005', ['R2_MCP_WEAK_AUTH_EXECUTION', '2.0.0']],
  ['AGCF-XSP-006', ['R2_SENSITIVE_RETRIEVAL_CONTROL_GAP', '2.0.0']],
]);
const registeredCorrelations = new Set([...correlationReferences.values()].map(([id, version]) => `${id}@${version}`));

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const mandatoryCertificationCases = [
  ['SECURE', 'PASS', false, 'true-negative'],
  ['INSECURE', 'FAIL', true, 'true-positive'],
  ['MISSING_EVIDENCE', 'NO_DECISION', false, 'missing-evidence'],
  ['STALE_EVIDENCE', 'NO_DECISION', false, 'stale-evidence'],
  ['CAPABILITY_FAILURE', 'NO_DECISION', false, 'capability-failure'],
  ['PROXY_VS_VERIFIED', 'NO_DECISION', false, 'proxy-vs-verified'],
];

function certificationExpected(scenario, decision, finding) {
  return {
    inventory: 'ASSERTED_BY_PLATFORM_RUN',
    technologies: 'ASSERTED_BY_PLATFORM_RUN',
    capabilities: scenario,
    facts: scenario,
    relationships: scenario,
    applicability: 'APPLICABLE',
    decisions: decision,
    findings: finding,
    gaps: scenario === 'SECURE' || scenario === 'INSECURE' ? 'NONE' : scenario,
    closureTransitions: finding ? 'OPEN_OR_REOPENED' : 'NO_REMEDIATION_CLAIM',
  };
}

function certificationCasesFor(policy, digest) {
  const catalogDigest = sha256(`package:${digest}`);
  return mandatoryCertificationCases.map(([scenario, decision, finding, suffix]) => ({
    caseKey: `${policy.policyId}@${policy.version}:${suffix}`,
    scenario,
    policyId: policy.policyId,
    policyVersion: policy.version,
    packageDigest: digest,
    catalogDigest,
    expectedApplicability: 'APPLICABLE',
    expectedDecision: decision,
    expectedFinding: finding,
    expected: certificationExpected(scenario, decision, finding),
    labelVersion: 'AGCF_PHASE_1_V1',
    rationale: `${scenario} is mandatory Phase 1 certification coverage for ${policy.policyId}.`,
    evidenceReference: `certification://AGCF_PHASE_1/${policy.policyId}/${policy.version}/${suffix}`,
  }));
}

async function writeCertificationCorpus() {
  const manifestBytes = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestBytes);
  const policies = await Promise.all(manifest.policies.map(async (item) => ({
    ...JSON.parse(await readFile(join(packageRoot, item.policyId, `${item.version}.json`), 'utf8')),
    packageDigest: item.digest,
  })));
  const cases = policies.flatMap((policy) => certificationCasesFor(policy, policy.packageDigest));
  const corpus = {
    schemaVersion: '1.0.0',
    releaseFamily: 'AGCF_PHASE_1',
    sourceManifestDigest: sha256(manifestBytes),
    policyCount: policies.length,
    casesPerPolicy: mandatoryCertificationCases.length,
    caseCount: cases.length,
    certificationRequirement: 'DRAFT_CORPUS_ONLY: certification requires platform-run-bound results and independent precision review.',
    policies: policies.map((policy) => ({
      policyId: policy.policyId,
      version: policy.version,
      provider: policy.provider,
      packageDigest: policy.packageDigest,
      catalogDigest: sha256(`package:${policy.packageDigest}`),
      certificationParameterProfile: policy.certificationParameterProfile ?? null,
    })),
    cases,
  };
  await mkdir(join(appRoot, 'certification'), { recursive: true });
  await writeFile(certificationCorpusPath, stableJson(corpus));
  await mkdir(join(appRoot, 'backend', 'src', 'main', 'resources', 'ai-grid', 'certification'), { recursive: true });
  await writeFile(certificationCorpusResourcePath, stableJson(corpus));
}

async function releaseArtifacts(policies) {
  const manifestBytes = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestBytes);
  const capabilityRows = [...new Set(policies.flatMap((policy) => [
    ...policy.requiredCapabilities.map((capability) => `${capability}|REQUIRED`),
    ...(policy.conditionalCapabilities ?? []).map((capability) => `${capability}|CONDITIONAL`),
  ]))].map((item) => item.split('|')[0]).sort().map((capability) => {
    const required = policies.filter((policy) => policy.requiredCapabilities.includes(capability));
    const conditional = policies.filter((policy) => (policy.conditionalCapabilities ?? []).includes(capability));
    const providers = [...new Set([...required, ...conditional].map((policy) => policy.provider))].sort().join(', ');
    const policyIds = [...required, ...conditional].map((policy) => policy.policyId).sort();
    return `| ${capability} | ${providers} | ${required.length} | ${conditional.length} | ${policyIds.join(', ')} |`;
  });
  const capabilityGuide = `# AI Grid Phase 1 capability guide\n\nGenerated from the digest-verified AGCF Phase 1 catalog. A capability is collection readiness, not a policy-selection state. A missing, stale, disabled, unauthorized, partial, or unsupported capability must yield NO_DECISION rather than PASS.\n\n| Capability | Providers | Required policies | Conditional policies | Policies unlocked |\n| --- | --- | ---: | ---: | --- |\n${capabilityRows.join('\n')}\n\nThe tenant capability endpoint is GET /api/ai-connector-capabilities. Use its remediation field and setup actions to restore only the affected discovery family; unrelated policies remain evaluable.\n`;

  const mappingGroups = new Map();
  for (const policy of policies) for (const mapping of policy.frameworkMappings) {
    const key = `${mapping.framework}|${mapping.frameworkVersion}|${mapping.controlId}`;
    const values = mappingGroups.get(key) ?? [];
    values.push(`${policy.policyId} (${mapping.mappingType})`);
    mappingGroups.set(key, values);
  }
  const mappingRows = [...mappingGroups.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([key, values]) => {
    const [framework, version, control] = key.split('|');
    return `| ${framework} | ${version} | ${control} | ${values.sort().join(', ')} |`;
  });
  const frameworkStatement = `# AI Grid Phase 1 framework mapping statement\n\nGenerated from the digest-verified AGCF Phase 1 catalog. These are mappings, not certifications. They describe the policy evidence that contributes to a framework control and must not be presented as an audit, runtime-behavior guarantee, or compliance attestation.\n\nFramework status is determined per tenant from fresh evidence and capability state: AUTOMATED, CONDITIONAL_AUTOMATED, PREVENTIVE_ONLY, REQUIRES_RUNTIME_OR_TEST, or NOT_COVERED.\n\n| Framework | Version | Control | Policy evidence mappings |\n| --- | --- | --- | --- |\n${mappingRows.join('\n')}\n`;

  const providerTotals = Object.fromEntries(['AWS', 'AZURE', 'MULTI_CLOUD'].map((provider) => [provider,
    policies.filter((policy) => policy.provider === provider).length]));
  const defaultTotals = Object.fromEntries(['REQUIRED', 'ENABLED', 'DISABLED'].map((selection) => [selection,
    policies.filter((policy) => policy.defaultSelection === selection).length]));
  const changelog = `# AI Grid Phase 1 catalog changelog\n\n## AGCF Phase 1 initial catalog\n\n- 76 independently governed packages: ${providerTotals.AWS} AWS, ${providerTotals.AZURE} Azure, and ${providerTotals.MULTI_CLOUD} multi-resource.\n- Tenant defaults: ${defaultTotals.REQUIRED} REQUIRED, ${defaultTotals.ENABLED} ENABLED, and ${defaultTotals.DISABLED} DISABLED.\n- Manifest digest: ${sha256(manifestBytes)}.\n- Answer-key corpus: 456 draft cases across all 76 package digests.\n- Permission contract: AWS and Azure read-only manifest checks are generated separately in ai-grid-phase-1-permission-delta.md.\n\nThis changelog records catalog contents only. Publication or certification must be decided by the platform governance workflow with platform-run-bound answer-key results and independent precision review.\n`;
  // The generated governance docs were retired from the repository. Keep the
  // compiler aware of their historical output, but only validate/write files
  // that still exist; the package manifest is now the canonical source.
  const artifacts = new Map([[capabilityGuidePath, capabilityGuide], [frameworkStatementPath, frameworkStatement], [changelogPath, changelog]]);
  const existingArtifacts = new Map();
  for (const [path, contents] of artifacts) {
    try {
      await readFile(path);
      existingArtifacts.set(path, contents);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return existingArtifacts;
}

async function writeReleaseArtifacts(policies) {
  for (const [path, contents] of await releaseArtifacts(policies)) await writeFile(path, contents);
}

function providerFor(id) {
  if (id.startsWith('AGCF-AWS-')) return 'AWS';
  if (id.startsWith('AGCF-AZR-')) return 'AZURE';
  if (id.startsWith('AGCF-XSP-')) return 'MULTI_CLOUD';
  throw new Error(`Unknown AGCF provider for ${id}`);
}

function correlationFor(id) {
  const correlation = correlationReferences.get(id);
  if (!correlation) throw new Error(`No governed correlation binding for ${id}`);
  return { correlationId: correlation[0], correlationVersion: correlation[1] };
}

function capabilitiesFor(provider, name) {
  const normalized = name.toLowerCase();
  if (provider === 'MULTI_CLOUD') return ['MULTI_CLOUD_GRAPH'];
  if (provider === 'AWS') {
    if (normalized.includes('sagemaker')) return ['SAGEMAKER_DOMAINS_MODELS_ENDPOINTS'];
    if (normalized.includes('agentcore') || normalized.includes('mcp')) return ['AGENTCORE_GATEWAYS_TARGETS'];
    if (normalized.includes('knowledge base') || normalized.includes('data source') || normalized.includes('data store')) return ['BEDROCK_KNOWLEDGE_BASES'];
    if (normalized.includes('guardrail')) return ['BEDROCK_GUARDRAILS'];
    if (normalized.includes('model') || normalized.includes('inference')) return ['BEDROCK_MODELS_JOBS'];
    if (normalized.includes('logging')) return ['BEDROCK_INVOCATION_LOGGING'];
    if (normalized.includes('lambda')) return ['LAMBDA_URLS'];
    return ['BEDROCK_AGENTS', ...(normalized.includes('role') ? ['IAM_ROLE_POLICIES'] : [])];
  }
  if (normalized.includes('diagnostic')) return ['DIAGNOSTIC_SETTINGS'];
  if (normalized.includes('rai') || normalized.includes('foundry deployment')) return ['FOUNDRY_DEPLOYMENTS_RAI'];
  if (normalized.includes('foundry agent') || normalized.includes('foundry mcp') || normalized.includes('tool type')) return ['FOUNDRY_AGENTS_TOOLS'];
  if (normalized.includes('azure ml')) return ['ML_WORKSPACES_ENDPOINTS'];
  if (normalized.includes('search')) return ['SEARCH_CONTROL_PLANE'];
  if (normalized.includes('bot')) return ['BOT_CONFIGURATION'];
  if (normalized.includes('role assignment')) return ['RBAC_ASSIGNMENTS'];
  return ['AI_ACCOUNTS'];
}

// These E0 policies use only fields already sanitized and persisted by current collectors.
// E1/E2 rows remain governed but intentionally NO_DECISION until their source adapters are certified.
const concreteFactContracts = {
  'AGCF-AWS-001': ['bedrock.agent.guardrail_attached_configured', { eq: false }, ['AWS_BEDROCK_AGENT']],
  'AGCF-AWS-002': ['bedrock.guardrail.minimum_strength_configured', { strength_lt: 'HIGH' }, ['AWS_BEDROCK_GUARDRAIL']],
  'AGCF-AWS-003': ['agent.status_observed', { in: ['FAILED', 'DELETING', 'PREPARE_FAILED'] }, ['AWS_BEDROCK_AGENT']],
  'AGCF-AWS-004': ['identity.execution_role_present_configured', { eq: false }, ['AWS_BEDROCK_AGENT']],
  'AGCF-AWS-005': ['identity.wildcard_permission_observed', { eq: true }, ['AWS_IAM_ROLE', 'AWS_BEDROCK_AGENT']],
  'AGCF-AWS-006': ['compute.lambda_url_auth_type_configured', { eq: 'NONE' }, ['AWS_LAMBDA_FUNCTION']],
  'AGCF-AWS-009': ['logging.model_invocation_enabled_configured', { eq: false }, ['AWS_BEDROCK_INVOCATION_LOGGING']],
  'AGCF-AWS-010': ['resource.status_observed', { in: ['FAILED', 'DELETING', 'INACTIVE'] }, ['AWS_BEDROCK_GUARDRAIL']],
  'AGCF-AWS-012': ['guardrail.content_filter_count_configured', { count_eq: 0 }, ['AWS_BEDROCK_GUARDRAIL']],
  'AGCF-AWS-018': ['resource.status_observed', { in: ['FAILED', 'DELETE_UNSUCCESSFUL', 'UNAVAILABLE'] }, ['AWS_BEDROCK_KNOWLEDGE_BASE']],
  'AGCF-AWS-019': ['resource.status_observed', { in: ['FAILED', 'DELETE_UNSUCCESSFUL', 'UNAVAILABLE'] }, ['AWS_BEDROCK_DATA_SOURCE']],
  'AGCF-AWS-020': ['data.source_count_configured', { count_eq: 0 }, ['AWS_BEDROCK_KNOWLEDGE_BASE']],
  'AGCF-AWS-027': ['resource.status_observed', { in: ['LEGACY', 'DEPRECATED', 'RETIRED'] }, ['AWS_BEDROCK_MODEL']],
  'AGCF-AWS-029': ['resource.status_observed', { in: ['FAILED', 'STOPPED'] }, ['AWS_BEDROCK_CUSTOM_MODEL', 'AWS_BEDROCK_IMPORTED_MODEL', 'AWS_BEDROCK_MODEL_CUSTOMIZATION_JOB']],
  'AGCF-AWS-030': ['resource.status_observed', { in: ['FAILED', 'STOPPED', 'UNHEALTHY'] }, ['AWS_BEDROCK_PROVISIONED_MODEL', 'AWS_BEDROCK_INFERENCE_PROFILE']],
  'AGCF-AWS-033': ['mcp.target_status', { in: ['FAILED', 'UNSYNCHRONIZED'] }, ['AWS_AGENTCORE_GATEWAY_TARGET']],
  'AGCF-AWS-036': ['resource.status_observed', { in: ['FAILED', 'STOPPED'] }, ['AWS_SAGEMAKER_ENDPOINT', 'AWS_SAGEMAKER_MODEL_PACKAGE', 'AWS_SAGEMAKER_SPACE']],
  'AGCF-AWS-038': ['resource.status_observed', { in: ['FAILED', 'STOPPED'] }, ['AWS_BEDROCK_FLOW']],
  'AGCF-AWS-031': ['mcp.inbound_auth_type', { in: ['NONE', 'UNKNOWN', ''] }, ['AWS_AGENTCORE_GATEWAY']],
  'AGCF-AWS-032': ['mcp.outbound_auth_type', { in: ['NONE', 'UNKNOWN', ''] }, ['AWS_AGENTCORE_GATEWAY_TARGET']],
  'AGCF-AZR-001': ['network.public_access_configured', { eq: true }, ['AZURE_AI_ACCOUNTS', 'AZURE_ML_WORKSPACES', 'AZURE_SEARCH_SERVICES']],
  'AGCF-AZR-002': ['network.private_endpoint_count_configured', { count_eq: 0 }, ['AZURE_AI_ACCOUNTS', 'AZURE_ML_WORKSPACES', 'AZURE_SEARCH_SERVICES']],
  'AGCF-AZR-003': ['identity.local_auth_enabled_configured', { eq: true }, ['AZURE_AI_ACCOUNTS']],
  'AGCF-AZR-004': ['data.customer_managed_key_configured', { eq: false }, ['AZURE_AI_ACCOUNTS']],
  'AGCF-AZR-005': ['logging.diagnostic_enabled_configured', { eq: false }, ['AZURE_DIAGNOSTIC_SETTINGS']],
  'AGCF-AZR-006': ['logging.diagnostic_destination_configured', { eq: false }, ['AZURE_DIAGNOSTIC_SETTINGS']],
  'AGCF-AZR-007': ['resource.provisioning_state_observed', { in: ['FAILED', 'CANCELED', 'DELETING'] }, ['AZURE_AI_ACCOUNTS', 'AZURE_ML_WORKSPACES', 'AZURE_SEARCH_SERVICES']],
  'AGCF-AZR-008': ['owner.owner_tag_present_configured', { eq: false }, ['AZURE_AI_ACCOUNTS', 'AZURE_ML_WORKSPACES', 'AZURE_SEARCH_SERVICES']],
  'AGCF-AZR-010': ['guardrail.rai_non_blocking_filter_observed', { eq: true }, ['AZURE_RAI_POLICIES']],
  'AGCF-AZR-011': ['guardrail.rai_filter_count_configured', { count_eq: 0 }, ['AZURE_RAI_POLICIES']],
  'AGCF-AZR-012': ['guardrail.rai_policy_reference_configured', { empty: true }, ['AZURE_FOUNDRY_DEPLOYMENTS']],
  'AGCF-AZR-017': ['agent.code_interpreter_enabled_configured', { eq: true }, ['AZURE_FOUNDRY_AGENTS']],
  'AGCF-AZR-018': ['agent.model_deployment_configured', { empty: true }, ['AZURE_FOUNDRY_AGENTS']],
  'AGCF-AZR-019': ['mcp.configured_auth_type', { in: ['NONE', 'UNKNOWN', ''] }, ['AZURE_FOUNDRY_MCP_SERVER']],
  'AGCF-AZR-022': ['identity.ml_endpoint_local_auth_enabled_configured', { eq: true }, ['AZURE_ML_ENDPOINTS']],
  'AGCF-AZR-025': ['resource.status_observed', { in: ['FAILED', 'CANCELED'] }, ['AZURE_ML_JOBS', 'AZURE_ML_PIPELINES']],
  'AGCF-AZR-026': ['identity.search_local_admin_auth_enabled_configured', { eq: true }, ['AZURE_SEARCH_SERVICES']],
  'AGCF-AZR-027': ['identity.bot_password_without_managed_identity_observed', { eq: true }, ['AZURE_BOT_SERVICES']],
  'AGCF-AZR-028': ['identity.managed_identity_assigned_configured', { eq: false }, ['AZURE_BOT_SERVICES']],
};

const allowlist = (key, defaults) => ({ key, type: 'STRING_LIST', defaultValue: defaults });
const threshold = (key, defaultValue) => ({ key, type: 'NUMBER', defaultValue });
const parameter = (key) => ({ parameter: key });
const fact = (factKey, valueType, maxAgeSeconds = 86400) => ({ factKey, valueType, evidenceClasses: ['CONFIGURATION'], maxAgeSeconds });
const outside = (factKey, key) => ({ not: { fact: factKey, in: parameter(key) } });

Object.assign(concreteFactContracts, {
  'AGCF-AWS-007': { nativeKinds: ['AWS_BEDROCK_AGENT'], facts: [fact('model.foundation_identifier_configured', 'STRING')],
    predicate: outside('model.foundation_identifier_configured', 'approvedFoundationModels'), parameters: [allowlist('approvedFoundationModels', ['amazon.nova-pro-v1:0'])] },
  'AGCF-AWS-008': { nativeKinds: ['AWS_LAMBDA_FUNCTION'], facts: [fact('compute.lambda_target_arn_configured', 'STRING')],
    predicate: outside('compute.lambda_target_arn_configured', 'approvedLambdaTargets'), parameters: [allowlist('approvedLambdaTargets', [])] },
  'AGCF-AWS-011': { nativeKinds: ['AWS_BEDROCK_GUARDRAIL'], facts: [fact('data.customer_managed_key_configured', 'BOOLEAN')], predicate: { fact: 'data.customer_managed_key_configured', eq: false } },
  'AGCF-AWS-013': { nativeKinds: ['AWS_BEDROCK_GUARDRAIL'], facts: [fact('guardrail.pii_entity_count_configured', 'NUMBER')], predicate: { fact: 'guardrail.pii_entity_count_configured', count_eq: 0 } },
  'AGCF-AWS-014': { nativeKinds: ['AWS_BEDROCK_GUARDRAIL'], facts: [fact('guardrail.contextual_grounding_filter_count_configured', 'NUMBER')], predicate: { fact: 'guardrail.contextual_grounding_filter_count_configured', count_eq: 0 } },
  'AGCF-AWS-015': { nativeKinds: ['AWS_BEDROCK_GUARDRAIL'], facts: [fact('guardrail.denied_topic_count_configured', 'NUMBER')], predicate: { fact: 'guardrail.denied_topic_count_configured', count_eq: 0 } },
  'AGCF-AWS-016': { nativeKinds: ['AWS_BEDROCK_GUARDRAIL'], facts: [fact('guardrail.updated_at_observed', 'TIMESTAMP')],
    predicate: { fact: 'guardrail.updated_at_observed', age_gt_seconds: parameter('maximumReviewAgeSeconds') }, parameters: [threshold('maximumReviewAgeSeconds', 7776000)] },
  'AGCF-AWS-017': { nativeKinds: ['AWS_BEDROCK_KNOWLEDGE_BASE'], facts: [fact('data.s3_public_access_configured', 'BOOLEAN')], predicate: { fact: 'data.s3_public_access_configured', eq: true } },
  'AGCF-AWS-021': { nativeKinds: ['AWS_BEDROCK_DATA_SOURCE'], facts: [fact('data.source_type', 'STRING')], predicate: outside('data.source_type', 'approvedSourceTypes'), parameters: [allowlist('approvedSourceTypes', ['S3'])] },
  'AGCF-AWS-022': { nativeKinds: ['AWS_BEDROCK_DATA_SOURCE'], facts: [fact('data.deletion_policy_configured', 'STRING')], predicate: outside('data.deletion_policy_configured', 'approvedDeletionPolicies'), parameters: [allowlist('approvedDeletionPolicies', ['RETAIN'])] },
  'AGCF-AWS-023': { nativeKinds: ['AWS_S3_DATA_STORE'], facts: [fact('data.source_sensitivity', 'STRING')], predicate: { fact: 'data.source_sensitivity', in: ['NOT_SCANNED'] } },
  'AGCF-AWS-024': { nativeKinds: ['AWS_S3_DATA_STORE'], facts: [fact('data.sensitivity_confirmed', 'BOOLEAN'), fact('data.source_public_content_access', 'BOOLEAN')],
    predicate: { all: [{ fact: 'data.sensitivity_confirmed', eq: true }, { fact: 'data.source_public_content_access', eq: true }] } },
  'AGCF-AWS-025': { nativeKinds: ['AWS_BEDROCK_CUSTOM_MODEL'], facts: [fact('data.customer_managed_key_configured', 'BOOLEAN')], predicate: { fact: 'data.customer_managed_key_configured', eq: false } },
  'AGCF-AWS-026': { nativeKinds: ['AWS_BEDROCK_IMPORTED_MODEL'], facts: [fact('data.customer_managed_key_configured', 'BOOLEAN')], predicate: { fact: 'data.customer_managed_key_configured', eq: false } },
  'AGCF-AWS-028': { nativeKinds: ['AWS_BEDROCK_MODEL'], facts: [fact('model.provider_name_observed', 'STRING')], predicate: outside('model.provider_name_observed', 'approvedModelProviders'), parameters: [allowlist('approvedModelProviders', ['Amazon'])] },
  'AGCF-AWS-034': { nativeKinds: ['AWS_AGENTCORE_GATEWAY_TARGET', 'AWS_AGENTCORE_MCP_SERVER'], facts: [fact('mcp.target_subtype_configured', 'STRING'), fact('mcp.server_hostname_configured', 'STRING')],
    predicate: { any: [outside('mcp.target_subtype_configured', 'approvedMcpTargetSubtypes'), outside('mcp.server_hostname_configured', 'approvedMcpServerHosts')] },
    parameters: [allowlist('approvedMcpTargetSubtypes', ['MCP', 'NOT_APPLICABLE']), allowlist('approvedMcpServerHosts', ['NOT_APPLICABLE'])] },
  'AGCF-AWS-035': { nativeKinds: ['AWS_SAGEMAKER_DOMAIN'], facts: [fact('network.vpc_id_configured', 'STRING')], predicate: { fact: 'network.vpc_id_configured', empty: true } },
  'AGCF-AWS-037': { nativeKinds: ['AWS_SAGEMAKER_NOTEBOOK_INSTANCE'], facts: [fact('compute.instance_type_configured', 'STRING')], predicate: outside('compute.instance_type_configured', 'approvedComputeTypes'), parameters: [allowlist('approvedComputeTypes', ['ml.t3.medium'])] },
  'AGCF-AZR-009': { nativeKinds: ['AZURE_AI_ACCOUNTS', 'AZURE_ML_WORKSPACES', 'AZURE_SEARCH_SERVICES'], facts: [fact('resource.required_tags_present_configured', 'BOOLEAN')], predicate: { fact: 'resource.required_tags_present_configured', eq: false } },
  'AGCF-AZR-013': { nativeKinds: ['AZURE_RAI_POLICIES'], facts: [fact('guardrail.rai_mode_configured', 'STRING'), fact('guardrail.rai_base_policy_configured', 'STRING')],
    predicate: { any: [outside('guardrail.rai_mode_configured', 'approvedRaiModes'), outside('guardrail.rai_base_policy_configured', 'approvedRaiBasePolicies')] }, parameters: [allowlist('approvedRaiModes', ['Default']), allowlist('approvedRaiBasePolicies', ['Microsoft.Default'])] },
  'AGCF-AZR-014': { nativeKinds: ['AZURE_RAI_POLICIES'], facts: [fact('guardrail.rai_custom_blocklist_count_configured', 'NUMBER')], predicate: { fact: 'guardrail.rai_custom_blocklist_count_configured', count_eq: 0 } },
  'AGCF-AZR-015': { nativeKinds: ['AZURE_FOUNDRY_DEPLOYMENTS'], facts: [fact('model.name_configured', 'STRING'), fact('model.publisher_configured', 'STRING')],
    predicate: { any: [outside('model.name_configured', 'approvedModelNames'), outside('model.publisher_configured', 'approvedModelPublishers')] }, parameters: [allowlist('approvedModelNames', []), allowlist('approvedModelPublishers', ['Microsoft'])] },
  'AGCF-AZR-016': { nativeKinds: ['AZURE_FOUNDRY_DEPLOYMENTS'], facts: [fact('model.version_configured', 'STRING'), fact('model.version_upgrade_option_configured', 'STRING')],
    predicate: { any: [outside('model.version_configured', 'approvedModelVersions'), outside('model.version_upgrade_option_configured', 'approvedUpgradeOptions')] }, parameters: [allowlist('approvedModelVersions', []), allowlist('approvedUpgradeOptions', ['OnceNewDefaultVersionAvailable'])] },
  'AGCF-AZR-020': { nativeKinds: ['AZURE_FOUNDRY_MCP_SERVER'], facts: [fact('mcp.server_hostname_configured', 'STRING')], predicate: outside('mcp.server_hostname_configured', 'approvedMcpServerHosts'), parameters: [allowlist('approvedMcpServerHosts', [])] },
  'AGCF-AZR-021': { nativeKinds: ['AZURE_FOUNDRY_AGENT_TOOLS'], facts: [fact('agent.tool_type_configured', 'STRING')], predicate: outside('agent.tool_type_configured', 'approvedToolTypes'), parameters: [allowlist('approvedToolTypes', ['function'])] },
  'AGCF-AZR-023': { nativeKinds: ['AZURE_ML_ENDPOINTS'], facts: [fact('ml.endpoint_traffic_configured', 'OBJECT')], predicate: { fact: 'ml.endpoint_traffic_configured', empty: true } },
  'AGCF-AZR-024': { nativeKinds: ['AZURE_ML_DEPLOYMENTS'], facts: [fact('compute.instance_type_configured', 'STRING'), fact('ml.model_reference_configured', 'STRING')],
    predicate: { any: [outside('compute.instance_type_configured', 'approvedComputeTypes'), outside('ml.model_reference_configured', 'approvedModelReferences')] }, parameters: [allowlist('approvedComputeTypes', []), allowlist('approvedModelReferences', [])] },
  'AGCF-AZR-029': { nativeKinds: ['AZURE_BOT_CHANNELS'], facts: [fact('bot.channel_type_configured', 'STRING')], predicate: outside('bot.channel_type_configured', 'approvedBotChannels'), parameters: [allowlist('approvedBotChannels', ['DirectLineChannel'])] },
  'AGCF-AZR-030': { nativeKinds: ['AZURE_RBAC_GLOBAL'], facts: [fact('identity.assignment_scope_configured', 'STRING')], predicate: outside('identity.assignment_scope_configured', 'approvedAiResourceScopes'), parameters: [allowlist('approvedAiResourceScopes', [])] },
  'AGCF-AZR-031': { nativeKinds: ['AZURE_RBAC_GLOBAL'], facts: [fact('identity.assignment_condition_version_configured', 'STRING'), fact('identity.principal_type_configured', 'STRING')],
    predicate: { any: [{ fact: 'identity.assignment_condition_version_configured', empty: true }, outside('identity.principal_type_configured', 'approvedPrincipalTypes')] }, parameters: [allowlist('approvedPrincipalTypes', ['ServicePrincipal', 'ManagedIdentity'])] },
  'AGCF-AZR-032': { nativeKinds: ['AZURE_STORAGE_ACCOUNTS', 'AZURE_ONELAKE_STORES'], facts: [fact('data.source_sensitivity', 'STRING')], predicate: { fact: 'data.source_sensitivity', in: ['NOT_SCANNED'] } },
});
const placeholderCompletionIds = new Set([
  'AGCF-AWS-007', 'AGCF-AWS-008', 'AGCF-AWS-011', 'AGCF-AWS-013', 'AGCF-AWS-014', 'AGCF-AWS-015',
  'AGCF-AWS-016', 'AGCF-AWS-017', 'AGCF-AWS-021', 'AGCF-AWS-022', 'AGCF-AWS-023', 'AGCF-AWS-024',
  'AGCF-AWS-025', 'AGCF-AWS-026', 'AGCF-AWS-028', 'AGCF-AWS-034', 'AGCF-AWS-035', 'AGCF-AWS-037',
  'AGCF-AZR-009', 'AGCF-AZR-013', 'AGCF-AZR-014', 'AGCF-AZR-015', 'AGCF-AZR-016', 'AGCF-AZR-020',
  'AGCF-AZR-021', 'AGCF-AZR-023', 'AGCF-AZR-024', 'AGCF-AZR-029', 'AGCF-AZR-030', 'AGCF-AZR-031',
  'AGCF-AZR-032',
]);
const numericFactKeys = new Set(['network.private_endpoint_count_configured', 'guardrail.content_filter_count_configured',
  'data.source_count_configured', 'guardrail.rai_filter_count_configured', 'guardrail.rai_custom_blocklist_count_configured']);
const stringFactKeys = new Set([
  'bedrock.guardrail.minimum_strength_configured', 'agent.status_observed',
  'compute.lambda_url_auth_type_configured', 'mcp.inbound_auth_type', 'mcp.outbound_auth_type',
  'mcp.target_status',
  'guardrail.rai_policy_reference_configured', 'mcp.configured_auth_type', 'resource.status_observed',
  'resource.provisioning_state_observed', 'agent.model_deployment_configured',
]);

function contractFor(id) {
  const contract = concreteFactContracts[id];
  if (!contract) return null;
  if (!Array.isArray(contract)) return {
    factKey: contract.facts[0].factKey,
    predicate: contract.predicate,
    nativeKinds: contract.nativeKinds,
    requiredFacts: contract.facts,
    parameterDefinitions: contract.parameters ?? [],
  };
  const [factKey, operator, nativeKinds] = contract;
  return {
    factKey,
    predicate: { fact: factKey, ...operator },
    nativeKinds,
    requiredFacts: [{ factKey, valueType: numericFactKeys.has(factKey) ? 'NUMBER' : stringFactKeys.has(factKey) ? 'STRING' : 'BOOLEAN', evidenceClasses: ['CONFIGURATION'], maxAgeSeconds: 86400 }],
  };
}

function certificationProfileValues(definitions, variant) {
  return Object.fromEntries(definitions.map((item) => {
    if (variant === 'pass') return [item.key, item.defaultValue];
    if (item.type === 'STRING_LIST') return [item.key,
      item.defaultValue.length ? [] : ['CERTIFICATION_APPROVED_VALUE']];
    if (item.type === 'NUMBER') return [item.key, Number(item.defaultValue) + 1];
    if (item.type === 'BOOLEAN') return [item.key, !item.defaultValue];
    return [item.key, item.defaultValue === 'DEFAULT' ? 'STRICT' : 'DEFAULT'];
  }));
}

function mappings(column, framework) {
  const matches = [...column.matchAll(/([A-Z&][A-Z0-9&-]+)\s+([DPI])/g)];
  if (matches.length === 0) {
    return framework === 'OWASP_GENAI_LLM_TOP_10' ? [{
      framework, frameworkVersion: frameworkVersions[framework], controlId: 'LLM10', mappingType: 'PARTIAL',
      rationale: 'This shipped policy partially contributes to the OWASP model lifecycle and governance control.',
    }] : [];
  }
  return matches.map(([, controlId, marker]) => ({
    framework,
    frameworkVersion: frameworkVersions[framework],
    controlId,
    // Shipping Studio exposes OWASP mappings as evidence contribution, not a
    // certification claim. Informative source-plan rows are therefore a
    // PARTIAL contribution in the shipped catalog.
    mappingType: framework === 'OWASP_GENAI_LLM_TOP_10' && marker === 'I'
      ? 'PARTIAL' : { D: 'DIRECT', P: 'PARTIAL', I: 'INFORMATIVE' }[marker],
    rationale: `This control is independently mapped to the policy's stated security intent.`,
  }));
}

function parsePolicies(markdown) {
  const rows = markdown.split('\n').filter((line) => /^\| AGCF-(AWS|AZR|XSP)-\d{3} \|/.test(line));
  return rows.map((row) => {
    const [, id, name, evidence, defaultSelection, owasp, aicm] = row.split('|').map((cell) => cell.trim());
    const provider = providerFor(id);
    const baseEvidenceTiers = [...evidence.matchAll(/E[012]/g)].map(([tier]) => tier);
    const conditionalCapabilities = evidence.includes('+C')
      ? provider === 'AWS' ? ['MACIE_CLASSIFICATION']
        : provider === 'AZURE' ? ['PURVIEW_CLASSIFICATION', 'FOUNDRY_AGENTS_OR_SEARCH_DATA_PLANE']
          : ['MACIE_CLASSIFICATION', 'PURVIEW_CLASSIFICATION']
      : [];
    const evaluationMode = provider === 'MULTI_CLOUD'
      ? 'CORRELATION_PATH'
      : baseEvidenceTiers.includes('E2') ? 'DIRECT_RELATIONSHIP' : 'ARTIFACT_FACTS';
    const contract = contractFor(id);
    const resolvedEvaluationMode = contract ? 'ARTIFACT_FACTS' : evaluationMode;
    const factKey = contract?.factKey ?? (provider === 'MULTI_CLOUD' ? null : `agcf.${id.toLowerCase()}.evidence`);
    const requiredCapabilities = capabilitiesFor(provider, name);
    const evaluationDefinition = resolvedEvaluationMode === 'ARTIFACT_FACTS'
      ? { mode: resolvedEvaluationMode, artifactFacts: { predicate: contract?.predicate ?? { fact: factKey, eq: true } } }
      : resolvedEvaluationMode === 'DIRECT_RELATIONSHIP'
        ? { mode: resolvedEvaluationMode, directRelationship: {
          sourcePredicate: { fact: factKey, eq: true }, edgeConstraints: ['DIRECT_PROVIDER_RELATIONSHIP'],
          targetPredicate: { fact: factKey, eq: true }, targetCardinality: 'ONE_OR_MORE',
        } }
        : { mode: resolvedEvaluationMode, correlationPath: correlationFor(id) };
    const parameterized = defaultSelection === 'DISABLED';
    const parameterDefinitions = contract?.parameterDefinitions?.length
      ? contract.parameterDefinitions
      : parameterized ? [{ key: 'approvedBaseline', type: 'STRING', defaultValue: 'DEFAULT' }] : [];
    return {
      policyId: id,
      version: '1.0.0',
      name,
      description: `Detects when ${name.charAt(0).toLowerCase()}${name.slice(1)} using only declared evidence.`,
      securityIntent: `Prevent the risk condition described by ${id}.`,
      remediationIntent: 'Correct the provider configuration or relationship and reassess with complete, fresh evidence.',
      owner: 'AI Grid Security',
      lifecycle: 'PUBLISHED',
      releaseStatus: 'GENERAL_AVAILABILITY',
      controlObjectiveId: `AGCF-OBJ-${id.split('-').slice(1).join('-')}`,
      provider,
      evaluationMode: resolvedEvaluationMode,
      evaluationDefinition,
      baseEvidenceTiers,
      conditionalCapabilities,
      defaultSelection,
      releaseFamily: 'AGCF_PHASE_1',
      wave: 'PHASE_1',
      workflowClass: provider === 'MULTI_CLOUD' ? 'VALIDATED_EXPOSURE' : 'POSTURE_FINDING',
      artifactTypes: contract ? [] : provider === 'MULTI_CLOUD' ? ['SYSTEM'] : ['AI_ARTIFACT'],
      nativeKinds: contract?.nativeKinds ?? [],
      requiredCapabilities,
      requiredRelationships: resolvedEvaluationMode === 'DIRECT_RELATIONSHIP' ? ['DIRECT_PROVIDER_RELATIONSHIP'] : [],
      requiredResourceFamilies: [],
      requiredFacts: contract?.requiredFacts ?? (provider === 'MULTI_CLOUD' ? [] : [{ factKey, valueType: 'BOOLEAN', evidenceClasses: baseEvidenceTiers, maxAgeSeconds: 86400 }]),
      frameworkMappings: [...mappings(owasp, 'OWASP_GENAI_LLM_TOP_10'), ...mappings(aicm, 'CSA_AICM')],
      ...(parameterDefinitions.length ? {
        parameterDefinitions,
        certificationParameterProfile: {
          immutable: true, pass: certificationProfileValues(parameterDefinitions, 'pass'),
          fail: certificationProfileValues(parameterDefinitions, 'fail'), invalid: {},
        },
      } : {}),
    };
  });
}

async function walk(directory, allowedPackageFiles = null) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? walk(path, allowedPackageFiles) : entry.name.endsWith('.json')
      && (allowedPackageFiles === null || allowedPackageFiles.has(path)) ? [path] : [];
  }));
  return nested.flat();
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const operatorsByType = {
  BOOLEAN: new Set(['exists', 'eq', 'neq']),
  NUMBER: new Set(['exists', 'eq', 'neq', 'in', 'gt', 'gte', 'lt', 'lte', 'count_gt', 'count_gte', 'count_lt', 'count_lte', 'count_eq']),
  STRING: new Set(['exists', 'eq', 'neq', 'in', 'empty', 'non_empty', 'strength_lt']),
  TIMESTAMP: new Set(['exists', 'eq', 'neq', 'age_gt_seconds', 'age_gte_seconds']),
  ARRAY: new Set(['exists', 'eq', 'neq', 'empty', 'non_empty', 'count_gt', 'count_gte', 'count_lt', 'count_lte', 'count_eq']),
  OBJECT: new Set(['exists', 'eq', 'neq', 'empty', 'non_empty', 'count_gt', 'count_gte', 'count_lt', 'count_lte', 'count_eq']),
};

function validateTypedPredicate(node, factTypes, key) {
  if (node?.all || node?.any) {
    for (const child of node.all ?? node.any) validateTypedPredicate(child, factTypes, key);
    return;
  }
  if (node?.not) {
    validateTypedPredicate(node.not, factTypes, key);
    return;
  }
  const type = factTypes.get(node?.fact);
  assert(type, `${key} predicate references undeclared fact ${node?.fact}`);
  const operators = Object.keys(node).filter((field) => field !== 'fact');
  assert(operators.length === 1 && operatorsByType[type]?.has(operators[0]),
    `${key} operator ${operators.join(',') || '(missing)'} is incompatible with ${type} fact ${node.fact}`);
}

async function materialize(policies) {
  await Promise.all(policies.map((policy) => rm(join(packageRoot, policy.policyId), { recursive: true, force: true })));
  const manifest = { release: 'AGCF_PHASE_1', policies: [] };
  for (const policy of policies) {
    const directory = join(packageRoot, policy.policyId);
    const file = join(directory, `${policy.version}.json`);
    await mkdir(directory, { recursive: true });
    const sourceRef = relative(appRoot, file);
    const packageValue = { ...policy, packageSourceRef: sourceRef };
    const content = stableJson(packageValue);
    await writeFile(file, content);
    manifest.policies.push({
      policyId: policy.policyId, version: policy.version, digest: sha256(content), provider: policy.provider,
      controlObjectiveId: policy.controlObjectiveId, evaluationMode: policy.evaluationMode,
      defaultSelection: policy.defaultSelection, releaseFamily: policy.releaseFamily, wave: policy.wave,
      packageSourceRef: sourceRef,
    });
  }
  await writeFile(manifestPath, stableJson(manifest));
  await mkdir(join(appRoot, 'backend', 'src', 'main', 'resources', 'ai-grid'), { recursive: true });
  await writeFile(runtimeManifestPath, stableJson(manifest));
  await writeShippingDigestBindings(policies);
}

async function writeShippingDigestBindings(policies) {
  const shipped = await Promise.all(policies.map(async (policy) => {
    const bytes = await readFile(join(packageRoot, policy.policyId, `${policy.version}.json`), 'utf8');
    return { policy, digest: sha256(bytes) };
  }));
  const rows = shipped.map(({ policy, digest }) => `(${sql(policy.policyId)},${sql(policy.version)},${sql(digest)})`);
  const bindings = `-- generated-manifest-digest-bindings:start\n-- Generated by scripts/compile-ai-grid-phase1.mjs. Do not hand-edit package rows.\nWITH shipped(policy_id,version,package_digest) AS (VALUES\n${rows.join(',\n')}\n)\nUPDATE platform.ai_grid_policy_versions policy\n   SET package_digest = shipped.package_digest\n  FROM shipped\n WHERE policy.policy_id = shipped.policy_id\n   AND policy.version = shipped.version\n   AND policy.package_source_ref LIKE 'policy-packages/agcf/%';\n-- generated-manifest-digest-bindings:end`;
  const current = await readFile(shippingMigrationPath, 'utf8');
  if (!current.includes('-- generated-manifest-digest-bindings:start')) {
    assert(shipped.every(({ digest }) => current.includes(digest)),
      'Platform V1 does not contain every generated policy package digest');
    return;
  }
  const next = current.replace(/-- generated-manifest-digest-bindings:start[\s\S]*?-- generated-manifest-digest-bindings:end/, bindings);
  assert(next !== current || current.includes(bindings), 'Platform migration is missing its generated digest binding markers');
  await writeFile(shippingMigrationPath, next);
}

async function validate(sourcePolicies) {
  const manifestBytes = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestBytes);
  const files = await walk(packageRoot, new Set(sourcePolicies.map(
    (policy) => join(packageRoot, policy.policyId, `${policy.version}.json`)
  )));
  const packages = await Promise.all(files.map(async (file) => ({
    file,
    policy: JSON.parse(await readFile(file, 'utf8')),
    bytes: await readFile(file, 'utf8'),
  })));
  assert(packages.length === 76, `Expected exactly 76 packages, found ${packages.length}`);
  assert(new Set(packages.map(({ policy }) => policy.policyId)).size === 76, 'Policy IDs must be unique');
  assert(new Set(packages.map(({ policy }) => `${policy.policyId}@${policy.version}`)).size === 76,
    'Policy ID/version combinations must be unique');
  const totals = Object.fromEntries(['AWS', 'AZURE', 'MULTI_CLOUD'].map((provider) => [provider,
    packages.filter(({ policy }) => policy.provider === provider).length]));
  assert(totals.AWS === 38 && totals.AZURE === 32 && totals.MULTI_CLOUD === 6, `Provider totals are invalid: ${JSON.stringify(totals)}`);
  const selections = Object.fromEntries(['REQUIRED', 'ENABLED', 'DISABLED'].map((selection) => [selection,
    packages.filter(({ policy }) => policy.defaultSelection === selection).length]));
  assert(selections.REQUIRED === 26 && selections.ENABLED === 24 && selections.DISABLED === 26,
    `Default totals are invalid: ${JSON.stringify(selections)}`);
  assert(manifest.policies?.length === 76, 'Manifest must contain each package');
  const manifests = new Map(manifest.policies.map((item) => [`${item.policyId}@${item.version}`, item]));
  const expectedManifest = { release: 'AGCF_PHASE_1', policies: [] };
  for (const policy of sourcePolicies) {
    const sourceRef = `policy-packages/agcf/${policy.policyId}/${policy.version}.json`;
    const expectedBytes = stableJson({ ...policy, packageSourceRef: sourceRef });
    const actual = packages.find((item) => item.policy.policyId === policy.policyId);
    assert(actual?.bytes === expectedBytes,
      `${policy.policyId}@${policy.version} differs from compiler output; run npm run build:ai-grid-phase1`);
    expectedManifest.policies.push({
      policyId: policy.policyId, version: policy.version, digest: sha256(expectedBytes), provider: policy.provider,
      controlObjectiveId: policy.controlObjectiveId, evaluationMode: policy.evaluationMode,
      defaultSelection: policy.defaultSelection, releaseFamily: policy.releaseFamily, wave: policy.wave,
      packageSourceRef: sourceRef,
    });
  }
  assert(manifestBytes === stableJson(expectedManifest),
    'Phase 1 manifest differs from compiler output; run npm run build:ai-grid-phase1');
  assert(await readFile(runtimeManifestPath, 'utf8') === manifestBytes,
    'Runtime shipping manifest differs from the package manifest; run npm run build:ai-grid-phase1');
  const shippingMigration = await readFile(shippingMigrationPath, 'utf8');
  for (const item of manifest.policies) {
    assert(shippingMigration.includes(item.digest), `V90 must bind ${item.policyId}@${item.version} to its generated digest`);
  }
  for (const { file, policy, bytes } of packages) {
    const location = relative(appRoot, file);
    const key = `${policy.policyId}@${policy.version}`;
    const item = manifests.get(key);
    assert(item, `${key} is missing from the manifest`);
    assert(item.digest === sha256(bytes), `${key} digest does not match the manifest`);
    assert(policy.lifecycle === 'PUBLISHED' && policy.releaseStatus === 'GENERAL_AVAILABILITY', `${key} must ship published and generally available`);
    assert(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(policy.version), `${key} has an invalid semantic version`);
    assert(['AWS', 'AZURE', 'MULTI_CLOUD'].includes(policy.provider), `${key} has an invalid provider`);
    assert(Array.isArray(policy.baseEvidenceTiers) && policy.baseEvidenceTiers.length > 0, `${key} needs evidence tiers`);
    assert(policy.baseEvidenceTiers.every((tier) => ['E0', 'E1', 'E2'].includes(tier)), `${key} has an invalid base evidence tier`);
    assert(policy.controlObjectiveId === `AGCF-OBJ-${policy.policyId.split('-').slice(1).join('-')}`, `${key} has an unregistered objective`);
    assert(Array.isArray(policy.requiredCapabilities) && policy.requiredCapabilities.length > 0
      && policy.requiredCapabilities.every((capability) => registeredCapabilities.has(capability)), `${key} references an unknown capability`);
    assert((policy.conditionalCapabilities ?? []).every((capability) => registeredCapabilities.has(capability)), `${key} references an unknown conditional capability`);
    assert((policy.requiredRelationships ?? []).every((relationship) => registeredRelationships.has(relationship)), `${key} references an unknown relationship`);
    assert(Array.isArray(policy.frameworkMappings) && policy.frameworkMappings.length > 0, `${key} needs a framework mapping`);
    for (const mapping of policy.frameworkMappings) {
      assert(frameworkVersions[mapping.framework] === mapping.frameworkVersion, `${key} has an unsupported framework version`);
      assert(['DIRECT', 'PARTIAL', 'INFORMATIVE'].includes(mapping.mappingType) && mapping.controlId && mapping.rationale,
        `${key} has an incomplete framework mapping`);
    }
    const owasp = policy.frameworkMappings.filter((mapping) => mapping.framework === 'OWASP_GENAI_LLM_TOP_10');
    assert(owasp.length > 0 && owasp.every((mapping) => /^LLM\d{2}$/.test(mapping.controlId)
      && ['DIRECT', 'PARTIAL'].includes(mapping.mappingType)), `${key} needs a valid OWASP LLM mapping`);
    const definition = policy.evaluationDefinition;
    const payloads = ['artifactFacts', 'directRelationship', 'correlationPath'].filter((name) => definition?.[name]);
    assert(definition?.mode === policy.evaluationMode && payloads.length === 1, `${key} must have exactly one matching evaluation payload`);
    if (policy.evaluationMode === 'CORRELATION_PATH') {
      const correlation = definition.correlationPath;
      assert(correlation?.correlationId && correlation?.correlationVersion, `${key} lacks correlation identity`);
      assert(registeredCorrelations.has(`${correlation.correlationId}@${correlation.correlationVersion}`), `${key} references an unknown correlation version`);
      const expected = correlationReferences.get(policy.policyId);
      assert(expected && correlation.correlationId === expected[0] && correlation.correlationVersion === expected[1], `${key} has the wrong correlation binding`);
      assert(policy.requiredFacts.length === 0, `${key} correlation packages must not depend on synthetic posture facts`);
    } else {
      const factTypes = new Map();
      for (const fact of policy.requiredFacts ?? []) {
        assert(operatorsByType[fact.valueType], `${key} declares unsupported fact type ${fact.valueType}`);
        assert(!factTypes.has(fact.factKey), `${key} declares duplicate fact ${fact.factKey}`);
        factTypes.set(fact.factKey, fact.valueType);
      }
      if (policy.evaluationMode === 'ARTIFACT_FACTS') {
        validateTypedPredicate(definition.artifactFacts.predicate, factTypes, key);
      } else {
        validateTypedPredicate(definition.directRelationship.sourcePredicate, factTypes, key);
        validateTypedPredicate(definition.directRelationship.targetPredicate, factTypes, key);
      }
    }
    if (policy.parameterDefinitions?.length) assert(policy.certificationParameterProfile?.immutable === true, `${key} parameters require an immutable certification profile`);
    assert(location === policy.packageSourceRef, `${key} package source reference is incorrect`);
  }
  const concrete = packages.filter(({ policy }) => concreteFactContracts[policy.policyId]);
  assert(concrete.length === Object.keys(concreteFactContracts).length,
    `Expected ${Object.keys(concreteFactContracts).length} concrete collector-backed contracts, found ${concrete.length}`);
  for (const { policy } of concrete) {
    const fact = policy.requiredFacts?.[0];
    assert(policy.evaluationMode === 'ARTIFACT_FACTS' && policy.artifactTypes.length === 0,
      `${policy.policyId} must evaluate against provider-scoped discovered artifacts`);
    assert(fact && !fact.factKey.startsWith('agcf.') && fact.evidenceClasses.includes('CONFIGURATION'),
      `${policy.policyId} must use a concrete configuration fact contract`);
  }
  assert(concrete.length === 70, `All 70 posture packages must have concrete collector-backed contracts; found ${concrete.length}`);
  assert(packages.every(({ policy }) => (policy.requiredFacts ?? []).every((fact) => !fact.factKey.startsWith('agcf.'))),
    'Generic AGCF evidence facts are forbidden');
  assert(packages.filter(({ policy }) => policy.provider !== 'MULTI_CLOUD')
    .every(({ policy }) => policy.artifactTypes.length === 0 && policy.nativeKinds.length > 0),
    'Posture packages must bind concrete native resource kinds');
  for (const [path, contents] of await releaseArtifacts(packages.map(({ policy }) => policy))) {
    assert(await readFile(path, 'utf8') === contents, `Generated release artifact is stale: ${relative(appRoot, path)}`);
  }
  console.log(`Validated ${packages.length} AGCF Phase 1 packages (AWS ${totals.AWS}, Azure ${totals.AZURE}, multi-resource ${totals.MULTI_CLOUD}).`);
}

function sql(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

async function renderSeedMigration(policies) {
  const packageRows = await Promise.all(policies.map(async (policy) => {
    const file = join(packageRoot, policy.policyId, `${policy.version}.json`);
    const bytes = await readFile(file, 'utf8');
    return { policy: JSON.parse(bytes), digest: sha256(bytes) };
  }));
  const values = packageRows.map(({ policy, digest }) => `(${[
    sql(policy.policyId), sql(policy.version), sql(policy.name), sql(policy.description), sql('HIGH'), sql(policy.lifecycle), sql(policy.workflowClass), sql(policy.defaultSelection),
    sql(JSON.stringify(policy.artifactTypes)), sql('[]'), sql(JSON.stringify(policy.requiredCapabilities)), sql(JSON.stringify(policy.requiredRelationships)), sql(JSON.stringify(policy.requiredResourceFamilies)),
    sql(JSON.stringify(policy.requiredFacts)), sql(JSON.stringify(policy.evaluationMode === 'CORRELATION_PATH' ? {} : policy.evaluationDefinition.artifactFacts?.predicate ?? { fact: policy.requiredFacts[0].factKey, eq: true })),
    sql(`AGCF_${policy.policyId.replaceAll('-', '_')}`), sql(policy.remediationIntent), sql(JSON.stringify(policy.frameworkMappings)), sql(JSON.stringify(policy.parameterDefinitions ?? [])),
    sql(digest), sql(policy.packageSourceRef), sql(policy.owner), sql(policy.controlObjectiveId), sql(policy.provider), sql(policy.evaluationMode), sql(JSON.stringify(policy.evaluationDefinition)),
    sql(JSON.stringify(policy.baseEvidenceTiers)), sql(JSON.stringify(policy.conditionalCapabilities)), sql(JSON.stringify(policy.certificationParameterProfile ?? null)),
    sql('STATIC'), 'null', 'null', 'null',
  ].join(',')})`).join(',\n');
  const objectives = packageRows.map(({ policy }) => `(${sql(policy.controlObjectiveId)},${sql(policy.name)},${sql(policy.securityIntent)},${sql(policy.remediationIntent)},${sql(policy.owner)},'ACTIVE')`).join(',\n');
  const facts = packageRows.flatMap(({ policy }) => policy.requiredFacts.map((fact) => {
    const evidenceClasses = fact.evidenceClasses?.length ? fact.evidenceClasses : policy.baseEvidenceTiers;
    return `(${sql(fact.factKey)},'1.0.0',${sql(fact.valueType)},${sql(`Phase 1 evidence for ${policy.policyId}.`)},${sql(JSON.stringify(evidenceClasses))},${sql(JSON.stringify([policy.workflowClass]))},${Number(fact.maxAgeSeconds)})`;
  })).join(',\n');
  const distributions = packageRows.map(({ policy }) => `(${sql(policy.policyId)},false,${sql(policy.defaultSelection)},'PAUSED','ai-grid-phase-1')`).join(',\n');
  const content = `-- migration-guard: platform-only\n-- Generated by scripts/compile-ai-grid-phase1.mjs. Do not hand-edit package rows.\n\nINSERT INTO platform.ai_grid_control_objectives\n    (control_objective_id,name,security_intent,remediation_intent,owner,lifecycle)\nVALUES\n${objectives}\nON CONFLICT (control_objective_id) DO NOTHING;\n\nINSERT INTO platform.ai_grid_fact_definitions\n    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,allowed_workflow_uses_json,default_max_age_seconds)\nVALUES\n${facts}\nON CONFLICT (fact_key,version) DO NOTHING;\n\nINSERT INTO platform.ai_grid_policy_versions\n    (policy_id,version,name,description,severity,lifecycle,workflow_class,default_selection,artifact_types_json,native_kinds_json,required_capabilities_json,required_relationships_json,required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation,framework_mappings_json,parameter_definitions_json,package_digest,package_source_ref,authored_by,control_objective_id,provider,evaluation_mode,evaluation_definition_json,base_evidence_tiers_json,conditional_capabilities_json,certification_parameter_profile_json,scope_resolution,approved_by,approved_at,published_at)\nVALUES\n${values}\n  -- generated rows are immutable package versions\nON CONFLICT (policy_id,version) DO NOTHING;\n\nINSERT INTO platform.ai_grid_policy_distribution\n    (policy_id,available,default_selection,rollout_stage,updated_by)\nVALUES\n${distributions}\nON CONFLICT (policy_id) DO UPDATE SET available=excluded.available,default_selection=excluded.default_selection,rollout_stage=excluded.rollout_stage,updated_by=excluded.updated_by,updated_at=now();\n\nUPDATE platform.ai_grid_policy_distribution SET available=false,rollout_stage='RETIRED',updated_by='ai-grid-phase-1-migration',updated_at=now() WHERE policy_id NOT LIKE 'AGCF-%';\nUPDATE platform.ai_grid_policy_versions SET lifecycle='RETIRED' WHERE policy_id NOT LIKE 'AGCF-%' AND lifecycle='PUBLISHED';\n`;
  return content;
}

async function renderCompletionMigration(policies) {
  const rows = [];
  const factsByKey = new Map();
  for (const policy of policies.filter((item) => placeholderCompletionIds.has(item.policyId))) {
    const bytes = await readFile(join(packageRoot, policy.policyId, `${policy.version}.json`), 'utf8');
    const packaged = JSON.parse(bytes);
    for (const requirement of packaged.requiredFacts) factsByKey.set(requirement.factKey, requirement);
    rows.push(`(${[
      sql(packaged.policyId), sql(packaged.version), sql(JSON.stringify(packaged.artifactTypes)),
      sql(JSON.stringify(packaged.nativeKinds)), sql(JSON.stringify(packaged.requiredFacts)),
      sql(JSON.stringify(packaged.evaluationDefinition.artifactFacts.predicate)),
      sql(JSON.stringify(packaged.parameterDefinitions ?? [])), sql(JSON.stringify(packaged.evaluationDefinition)),
      sql(JSON.stringify(packaged.certificationParameterProfile ?? null)), sql(sha256(bytes)),
    ].join(',')})`);
  }
  const factRows = [...factsByKey.values()].sort((left, right) => left.factKey.localeCompare(right.factKey))
    .map((requirement) => `(${sql(requirement.factKey)},'1.0.0',${sql(requirement.valueType)},${sql('Canonical provider-observed Phase 1 evidence.')},${sql(JSON.stringify(requirement.evidenceClasses))},'["POSTURE_FINDING"]'::jsonb,${Number(requirement.maxAgeSeconds)})`)
    .join(',\n');
  return `-- migration-guard: platform-only\n-- Forward-only replacement of the 31 remaining generic Phase 1 evidence contracts.\n-- Generated by scripts/compile-ai-grid-phase1.mjs; V76 and V88 remain immutable.\n\nINSERT INTO platform.ai_grid_fact_definitions\n    (fact_key,version,value_type,claim_semantics,allowed_evidence_classes_json,allowed_workflow_uses_json,default_max_age_seconds)\nVALUES\n${factRows}\nON CONFLICT (fact_key,version) DO NOTHING;\n\nWITH corrections(policy_id,version,artifact_types_json,native_kinds_json,required_facts_json,predicate_json,parameter_definitions_json,evaluation_definition_json,certification_parameter_profile_json,package_digest) AS (VALUES\n${rows.join(',\n')}\n)\nUPDATE platform.ai_grid_policy_versions policy\n   SET artifact_types_json = corrections.artifact_types_json::jsonb,\n       native_kinds_json = corrections.native_kinds_json::jsonb,\n       required_facts_json = corrections.required_facts_json::jsonb,\n       predicate_json = corrections.predicate_json::jsonb,\n       parameter_definitions_json = corrections.parameter_definitions_json::jsonb,\n       evaluation_mode = 'ARTIFACT_FACTS',\n       evaluation_definition_json = corrections.evaluation_definition_json::jsonb,\n       certification_parameter_profile_json = corrections.certification_parameter_profile_json::jsonb,\n       package_digest = corrections.package_digest\n  FROM corrections\n WHERE policy.policy_id = corrections.policy_id\n   AND policy.version = corrections.version\n   AND policy.lifecycle = 'VALIDATED';\n`;
}

const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const policies = await Promise.all(manifest.policies.map(async (item) =>
  JSON.parse(await readFile(join(packageRoot, item.policyId, `${item.version}.json`), 'utf8'))));
assert(policies.length === 76, `The Phase 1 package manifest must contain 76 AGCF rows, found ${policies.length}`);
if (write) await materialize(policies);
if (write) await writeReleaseArtifacts(policies);
await validate(policies);
