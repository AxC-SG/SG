import React from 'react';
import { useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { normalizeConfigurationsRouteView, type ConfigurationsRouteView } from '../app/routes';
import { api } from '../api/client';
import { intelligenceApi } from '../features/intelligence/api';
import { useActor } from '../features/auth/context';
import { canManageRiskPolicy } from '../features/auth/roles';
import type { OwnershipRuleResponse, RiskPolicy, SuppressionCondition, SuppressionRule, SuppressionRuleRequest } from '../features/configurations/types';
import {
  DEFAULT_AUTO_FINDING_RULES,
  DEFAULT_AUTO_FINDING_RULES_STORAGE_KEY,
  DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
} from '../features/configurations/defaults';
import type { VulnerabilitySourceFilterConfig, VulnerabilitySourceFilterConfigRequest, VulnerabilitySourceSystem } from '../features/connect/types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { AsyncSection } from '../components/AsyncSection';
import { ConfirmDialog } from '../components/ConfirmDialog';
import {
  type AgentConfidenceLevel,
  type AssetInventoryCriterion,
  type EolAnalysisResult,
  type FalsePositiveResult,
  loadPersistedInvestigationRunbookState,
  persistInvestigationRunbookState,
} from '../features/cve-workbench/investigation-context';
import type {
  AssetCriterion,
  CveDetail,
  OrgSpecificCveExposureRecord,
  CreateServiceNowIncidentRequest,
  RunbookLogEntryRecord,
  RunbookTaskStateRecord,
} from '../features/cve-workbench/types';

type ConfigNavKey = ConfigurationsRouteView;

const AUTO_INVESTIGATION_RUNBOOK_TASK_IDS = [
  'review-asset-inventory',
  'find-false-positive',
  'end-of-life-analysis',
  'solutions',
  'installed-patch-info',
] as const;

interface TriageSignalDef {
  field: keyof Pick<
    RiskPolicy,
    | 'triageExploitabilityWeight'
    | 'triageBlastRadiusWeight'
    | 'triageEolRiskWeight'
    | 'triageSlaBreachWeight'
    | 'triageMissingOwnerBoost'
    | 'triagePatchGapBoost'
  >;
  label: string;
  icon: string;
  businessReason: string;
  urgencyTag: string;
}

const TRIAGE_SIGNALS: TriageSignalDef[] = [
  {
    field: 'triageExploitabilityWeight',
    label: 'Exploitability',
    icon: '⚡',
    businessReason:
      'KEV inclusion confirms the CVE is exploited in the wild. A high EPSS score is a probability that exploitation will be observed, not a confirmation. Both raise the urgency of patching.',
    urgencyTag: 'EPSS > 0.5 or in KEV',
  },
  {
    field: 'triageBlastRadiusWeight',
    label: 'Asset Blast Radius',
    icon: '📡',
    businessReason:
      'The more assets a vulnerability affects, the wider the breach impact if exploited. High blast radius means multiple teams must coordinate patching at the same time.',
    urgencyTag: '10+ matched assets',
  },
  {
    field: 'triageEolRiskWeight',
    label: 'EOL / End-of-Life Risk',
    icon: '⏱',
    businessReason:
      'Software past end-of-life receives no vendor patches. Vulnerabilities in EOL components are permanent until the software is replaced — not just delayed.',
    urgencyTag: 'EOL component affected',
  },
  {
    field: 'triageSlaBreachWeight',
    label: 'SLA Breach Proximity',
    icon: '📅',
    businessReason:
      'Items close to SLA deadline create audit and compliance exposure. Near-breach findings need unblocking now or the team needs escalation support.',
    urgencyTag: '< 5 days to SLA breach',
  },
  {
    field: 'triageMissingOwnerBoost',
    label: 'Missing Owner',
    icon: '👤',
    businessReason:
      'Findings with no assigned owner have no accountable team driving remediation. They age silently. Surfacing them early reduces chronic ownership gaps.',
    urgencyTag: 'No owner assigned',
  },
  {
    field: 'triagePatchGapBoost',
    label: 'Patch Gap',
    icon: '🔧',
    businessReason:
      'When no vendor fix exists, risk stays active until compensating controls are deployed. These findings need manual mitigation planning, not just a ticket to patch.',
    urgencyTag: 'No patch available',
  },
];

// ── Findings Score configuration ───────────────────────────────────────────

interface FindingsScoreValueWeight {
  operator: string;
  value: string;
  /** Optional second bound for range conditions on numeric columns (AND-ed with the first). */
  operator2?: string;
  value2?: string;
  weight: number; // 0–1
}

interface FindingsScoreColumn {
  table: string;
  column: string;
  values: FindingsScoreValueWeight[];
}

const FINDINGS_SCORE_TABLES = [
  { value: 'VULNERABILITY', label: 'Vulnerability' },
  { value: 'ASSET', label: 'Asset Inventory' },
  { value: 'SOFTWARE', label: 'Software' },
];

const FINDINGS_SCORE_COLUMNS: Record<string, Array<{ value: string; label: string }>> = {
  VULNERABILITY: [
    { value: 'description', label: 'Description' },
    { value: 'severity', label: 'Severity' },
    { value: 'cvssScore', label: 'CVSS Score' },
    { value: 'epssScore', label: 'EPSS Score' },
    { value: 'exploitExists', label: 'Exploit Available' },
    { value: 'isInKev', label: 'In CISA KEV' },
    { value: 'patchAvailable', label: 'Patch Available' },
    { value: 'attackVector', label: 'Attack Vector' },
    { value: 'attackComplexity', label: 'Attack Complexity' },
    { value: 'privilegesRequired', label: 'Privileges Required' },
    { value: 'userInteraction', label: 'User Interaction' },
    { value: 'scope', label: 'Scope' },
    { value: 'confidentialityImpact', label: 'Confidentiality Impact' },
    { value: 'integrityImpact', label: 'Integrity Impact' },
    { value: 'availabilityImpact', label: 'Availability Impact' },
  ],
  ASSET: [
    { value: 'businessCriticality', label: 'Business Criticality' },
    { value: 'internetFacing', label: 'Internet Facing' },
    { value: 'osType', label: 'OS Type' },
    { value: 'assetType', label: 'Asset Type' },
    { value: 'environment', label: 'Environment' },
    { value: 'status', label: 'Status' },
    { value: 'isEol', label: 'End of Life' },
    { value: 'region', label: 'Region / Location' },
    { value: 'owner', label: 'Owner' },
    { value: 'tags', label: 'Tags' },
  ],
  SOFTWARE: [
    { value: 'name', label: 'Software Name' },
    { value: 'vendor', label: 'Vendor' },
    { value: 'version', label: 'Version' },
    { value: 'packageType', label: 'Package Type' },
    { value: 'language', label: 'Language / Ecosystem' },
    { value: 'isEol', label: 'End of Life' },
    { value: 'license', label: 'License' },
    { value: 'purl', label: 'Package URL (purl)' },
  ],
};

// ── Findings Score — column types, operators, condition evaluation ─────────

type ColumnDataType = 'numeric' | 'string' | 'boolean' | 'enum';

const COLUMN_DATA_TYPES: Record<string, Record<string, ColumnDataType>> = {
  VULNERABILITY: {
    description: 'string', severity: 'enum', cvssScore: 'numeric', epssScore: 'numeric',
    exploitExists: 'boolean', isInKev: 'boolean', patchAvailable: 'boolean',
    attackVector: 'enum', attackComplexity: 'enum', privilegesRequired: 'enum',
    userInteraction: 'enum', scope: 'enum',
    confidentialityImpact: 'enum', integrityImpact: 'enum', availabilityImpact: 'enum',
  },
  ASSET: {
    businessCriticality: 'enum', internetFacing: 'boolean', osType: 'string',
    assetType: 'string', environment: 'enum', status: 'enum',
    isEol: 'boolean', region: 'string', owner: 'string', tags: 'string',
  },
  SOFTWARE: {
    name: 'string', vendor: 'string', version: 'string',
    packageType: 'enum', language: 'string', isEol: 'boolean',
    license: 'string', purl: 'string',
  },
};

const NUMERIC_OPS = [
  { value: '>', label: '>' }, { value: '<', label: '<' },
  { value: '>=', label: '>=' }, { value: '<=', label: '<=' },
  { value: '=', label: '=' }, { value: '!=', label: '!=' },
];
const STRING_OPS = [
  { value: 'contains', label: 'contains' },
  { value: 'not contains', label: 'not contains' },
  { value: 'exact match', label: 'exact match' },
];
const ENUM_OPS = [{ value: '=', label: 'is' }, { value: '!=', label: 'is not' }];
const BOOL_OPS  = [{ value: '=', label: 'is' }];

function getColumnDataType(table: string, column: string): ColumnDataType {
  return COLUMN_DATA_TYPES[table]?.[column] ?? 'string';
}
function getOperatorsForType(t: ColumnDataType) {
  if (t === 'numeric') return NUMERIC_OPS;
  if (t === 'boolean') return BOOL_OPS;
  if (t === 'enum') return ENUM_OPS;
  return STRING_OPS;
}
function defaultOperatorForType(t: ColumnDataType): string {
  if (t === 'numeric') return '>=';
  return '=';
}
function evaluateSingleCondition(op: string, ruleVal: string, actual: string, t: ColumnDataType): boolean {
  if (!ruleVal.trim() || actual === '') return false;
  if (t === 'numeric') {
    const rv = parseFloat(ruleVal);
    const av = parseFloat(actual);
    if (isNaN(rv) || isNaN(av)) return false;
    switch (op) {
      case '>':  return av > rv;
      case '<':  return av < rv;
      case '>=': return av >= rv;
      case '<=': return av <= rv;
      case '!=': return av !== rv;
      default:   return av === rv;
    }
  }
  if (t === 'string') {
    const lo = actual.toLowerCase();
    const rv = ruleVal.toLowerCase();
    if (op === 'contains') return lo.includes(rv);
    if (op === 'not contains') return !lo.includes(rv);
    return actual === ruleVal; // exact match
  }
  return op === '!=' ? actual !== ruleVal : actual === ruleVal;
}

function evaluateCondition(v: FindingsScoreValueWeight, actual: string, t: ColumnDataType): boolean {
  if (!evaluateSingleCondition(v.operator, v.value, actual, t)) return false;
  if (v.operator2 && v.value2 && v.value2.trim()) {
    return evaluateSingleCondition(v.operator2, v.value2, actual, t);
  }
  return true;
}

// ── Validation ──────────────────────────────────────────────────────────────

type PolicyValidationError = {
  field: keyof RiskPolicy;
  message: string;
};

function validateRiskPolicy(policy: RiskPolicy): PolicyValidationError[] {
  const errors: PolicyValidationError[] = [];
  const chk = (
    field: keyof RiskPolicy,
    value: number,
    min: number,
    max: number,
    label: string
  ): void => {
    if (Number.isNaN(value) || value < min || value > max) {
      errors.push({ field, message: `${label} must be between ${min} and ${max}.` });
    }
  };

  chk('criticalThreshold', policy.criticalThreshold, 0, 10, 'Critical threshold');
  chk('highThreshold', policy.highThreshold, 0, 10, 'High threshold');
  if (policy.highThreshold > policy.criticalThreshold) {
    errors.push({ field: 'highThreshold', message: 'High threshold cannot exceed critical threshold.' });
  }
  chk('criticalSlaDays', policy.criticalSlaDays, 0, 365, 'Critical SLA');
  chk('highSlaDays', policy.highSlaDays, 0, 365, 'High SLA');
  chk('mediumSlaDays', policy.mediumSlaDays, 0, 365, 'Medium SLA');
  chk('lowSlaDays', policy.lowSlaDays, 0, 365, 'Low SLA');
  chk('autoCloseAfterDays', policy.autoCloseAfterDays, 0, 365, 'Auto-close days');
  chk('autoCloseRequiredConsecutiveMisses', policy.autoCloseRequiredConsecutiveMisses, 1, 10, 'Required missed scans');
  chk('autoCloseRunIntervalDays', policy.autoCloseRunIntervalDays, 1, 365, 'Auto-close run schedule');
  chk('triageExploitabilityWeight', policy.triageExploitabilityWeight, 0, 2, 'Exploitability weight');
  chk('triageBlastRadiusWeight', policy.triageBlastRadiusWeight, 0, 2, 'Blast radius weight');
  chk('triageEolRiskWeight', policy.triageEolRiskWeight, 0, 2, 'EOL risk weight');
  chk('triageSlaBreachWeight', policy.triageSlaBreachWeight, 0, 2, 'SLA breach weight');
  chk('triageMissingOwnerBoost', policy.triageMissingOwnerBoost, 0, 2, 'Missing owner boost');
  chk('triagePatchGapBoost', policy.triagePatchGapBoost, 0, 2, 'Patch gap boost');
  return errors;
}

const SECTION_FIELDS: Partial<Record<ConfigNavKey, ReadonlyArray<keyof RiskPolicy>>> = {
  triage: [
    'triageExploitabilityWeight',
    'triageBlastRadiusWeight',
    'triageEolRiskWeight',
    'triageSlaBreachWeight',
    'triageMissingOwnerBoost',
    'triagePatchGapBoost',
  ],
  sla: [
    'criticalThreshold',
    'highThreshold',
    'criticalSlaDays',
    'highSlaDays',
    'mediumSlaDays',
    'lowSlaDays',
  ],
  automation: [
    'autoCloseEnabled',
    'autoCloseAfterDays',
    'autoCloseRequiredConsecutiveMisses',
    'autoCloseRunIntervalDays',
    'autoCloseNotObservedEnabled',
    'autoCloseComponentRemovedEnabled',
    'autoCloseAssetRetiredEnabled',
    'autoCloseSourceDisabledEnabled',
  ],
  ownership: [],
};

// Module-level helper — used in both useEffect (initial load) and savePolicy
// (after save response) so the triage sliders always have a numeric value even
// when the backend is running pre-V1062 and doesn't return these fields.
type TriageKeys =
  | 'triageExploitabilityWeight'
  | 'triageBlastRadiusWeight'
  | 'triageEolRiskWeight'
  | 'triageSlaBreachWeight'
  | 'triageMissingOwnerBoost'
  | 'triagePatchGapBoost';

function applyTriageDefaults(data: RiskPolicy): RiskPolicy {
  const base = data as Omit<RiskPolicy, TriageKeys>;
  const raw = data as unknown as Record<string, unknown>;
  return {
    ...base,
    triageExploitabilityWeight: (raw.triageExploitabilityWeight as number | undefined) ?? 1.0,
    triageBlastRadiusWeight: (raw.triageBlastRadiusWeight as number | undefined) ?? 1.0,
    triageEolRiskWeight: (raw.triageEolRiskWeight as number | undefined) ?? 0.8,
    triageSlaBreachWeight: (raw.triageSlaBreachWeight as number | undefined) ?? 1.2,
    triageMissingOwnerBoost: (raw.triageMissingOwnerBoost as number | undefined) ?? 0.5,
    triagePatchGapBoost: (raw.triagePatchGapBoost as number | undefined) ?? 0.3,
    autoCloseRequiredConsecutiveMisses: (raw.autoCloseRequiredConsecutiveMisses as number | undefined) ?? 2,
    autoCloseNotObservedEnabled: (raw.autoCloseNotObservedEnabled as boolean | undefined) ?? true,
    autoCloseComponentRemovedEnabled: (raw.autoCloseComponentRemovedEnabled as boolean | undefined) ?? true,
    autoCloseAssetRetiredEnabled: (raw.autoCloseAssetRetiredEnabled as boolean | undefined) ?? true,
    autoCloseSourceDisabledEnabled: (raw.autoCloseSourceDisabledEnabled as boolean | undefined) ?? false,
    autoCloseDuplicateEnabled: (raw.autoCloseDuplicateEnabled as boolean | undefined) ?? true,
    autoCloseRunIntervalDays: (raw.autoCloseRunIntervalDays as number | undefined) ?? 1,
    findingsScoreConfig: (raw.findingsScoreConfig as string | undefined) ?? DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
  };
}

const DEFAULT_RISK_POLICY: RiskPolicy = applyTriageDefaults({
  criticalThreshold: 9.0,
  highThreshold: 7.0,
  criticalSlaDays: 7,
  highSlaDays: 14,
  mediumSlaDays: 30,
  lowSlaDays: 60,
  assetCriticalSlaMultiplier: 0.5,
  assetHighSlaMultiplier: 0.75,
  assetMediumSlaMultiplier: 1.0,
  assetLowSlaMultiplier: 1.25,
  autoCloseEnabled: false,
  autoCloseAssetIdentifier: '',
  autoCloseAfterDays: 0,
  autoCloseRequiredConsecutiveMisses: 2,
  autoCloseNotObservedEnabled: true,
  autoCloseComponentRemovedEnabled: true,
  autoCloseAssetRetiredEnabled: true,
  autoCloseSourceDisabledEnabled: false,
  autoCloseDuplicateEnabled: true,
  autoCloseRunIntervalDays: 1,
  findingGenerationMode: 'AUTO',
  findingsScoreConfig: DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
  triageExploitabilityWeight: 1.0,
  triageBlastRadiusWeight: 1.0,
  triageEolRiskWeight: 0.8,
  triageSlaBreachWeight: 1.2,
  triageMissingOwnerBoost: 0.5,
  triagePatchGapBoost: 0.3,
});

type OwnershipRule = OwnershipRuleResponse;

type OwnershipConditionRow = {
  table: string;
  column: string;
  operator: string;
  value: string;
};

type OwnershipRuleForm = {
  name: string;
  conditionLogic: 'AND' | 'OR';
  conditions: OwnershipConditionRow[];
  userGroup: string;
};

function blankOwnershipRuleForm(): OwnershipRuleForm {
  return {
    name: '',
    conditionLogic: 'AND',
    conditions: [{ table: 'ASSET', column: 'owner', operator: '=', value: '' }],
    userGroup: '',
  };
}

function formatOwnershipCondition(row: OwnershipConditionRow): string {
  const tableLabel = FINDINGS_SCORE_TABLES.find((item) => item.value === row.table)?.label ?? row.table;
  const columnLabel = FINDINGS_SCORE_COLUMNS[row.table]?.find((item) => item.value === row.column)?.label ?? row.column;
  return `${tableLabel}.${columnLabel} ${row.operator} ${row.value || '—'}`;
}

function formatOwnershipRuleCondition(rule: OwnershipRule): string {
  try {
    const parsed = JSON.parse(rule.condition);
    if (parsed && typeof parsed === 'object' && Array.isArray(parsed.conditions)) {
      const logic = parsed.logic === 'OR' ? 'ANY' : 'ALL';
      const rows = parsed.conditions
        .map((row: OwnershipConditionRow) => formatOwnershipCondition(row))
        .join(` ${logic} `);
      return rows || 'No conditions';
    }
  } catch {
    // fall through to raw text
  }
  return rule.condition || 'No conditions';
}

function parseOwnershipRuleCondition(condition: string): OwnershipRuleForm {
  try {
    const parsed = JSON.parse(condition) as { logic?: 'AND' | 'OR'; conditions?: OwnershipConditionRow[] };
    if (parsed && Array.isArray(parsed.conditions)) {
      const conditions = parsed.conditions.length > 0
        ? parsed.conditions.map((row) => ({
          table: row.table || 'ASSET',
          column: row.column || 'owner',
          operator: row.operator || '=',
          value: row.value || '',
        }))
        : [{ table: 'ASSET', column: 'owner', operator: '=', value: '' }];
      return {
        name: '',
        conditionLogic: parsed.logic === 'OR' ? 'OR' : 'AND',
        conditions,
        userGroup: '',
      };
    }
  } catch {
    // Legacy free-text condition; present a blank builder row and keep the raw text as a cue.
  }
  return {
    name: '',
    conditionLogic: 'AND',
    conditions: [{ table: 'ASSET', column: 'owner', operator: '=', value: condition || '' }],
    userGroup: '',
  };
}


function scoreSeverityLabel(score: number): { label: string; color: string } {
  if (score >= 9) return { label: 'Critical', color: 'var(--dp-critical)' };
  if (score >= 7) return { label: 'High', color: 'var(--dp-high)' };
  if (score >= 4) return { label: 'Medium', color: 'var(--dp-medium)' };
  return { label: 'Low', color: 'var(--dp-low)' };
}

function fmt2(n: number): string {
  return n.toFixed(2);
}

export function ConfigurationsPage() {
  const actor = useActor();
  const queryClient = useQueryClient();
  const params = useParams<{ configView?: string }>();
  const riskPolicyQuery = useRiskPolicyQuery();
  const [policy, setPolicy] = React.useState<RiskPolicy | null>(null);
  const [policyMessage, setPolicyMessage] = React.useState('');
  const [policySaving, setPolicySaving] = React.useState(false);
  // Local edits not yet saved. A ref mirrors it so a background refetch never overwrites a draft.
  const [policyDirty, setPolicyDirtyState] = React.useState(false);
  const policyDirtyRef = React.useRef(false);
  const setPolicyDirty = (dirty: boolean) => {
    policyDirtyRef.current = dirty;
    setPolicyDirtyState(dirty);
  };
  const [autoCloseExecuting, setAutoCloseExecuting] = React.useState(false);
  const activeSection = normalizeConfigurationsRouteView(params.configView);

  React.useEffect(() => {
    setPolicyMessage('');
  }, [activeSection]);

  const canEditRiskPolicy = canManageRiskPolicy(actor);
  const [ownershipRules, setOwnershipRules] = React.useState<OwnershipRule[]>([]);
  const [ownershipGroups, setOwnershipGroups] = React.useState<string[]>([]);
  const [ownershipLoading, setOwnershipLoading] = React.useState(true);
  const [ownershipLoadError, setOwnershipLoadError] = React.useState(false);
  const [ownershipDeleteId, setOwnershipDeleteId] = React.useState<string | null>(null);
  const [ownershipDeleting, setOwnershipDeleting] = React.useState(false);
  const [ownershipDeleteError, setOwnershipDeleteError] = React.useState('');
  const [ownershipExecutingId, setOwnershipExecutingId] = React.useState<string | null>(null);
  const [ownershipShowForm, setOwnershipShowForm] = React.useState(false);
  const [ownershipEditingId, setOwnershipEditingId] = React.useState<string | null>(null);
  const [ownershipForm, setOwnershipForm] = React.useState<OwnershipRuleForm>(blankOwnershipRuleForm());
  const [ownershipMessage, setOwnershipMessage] = React.useState('');
  const [ownershipGroupOpen, setOwnershipGroupOpen] = React.useState(false);
  const ownershipGroupRef = React.useRef<HTMLLabelElement | null>(null);

  // Triage score live simulator state
  const [triageSimEpss, setTriageSimEpss] = React.useState(0.45);
  const [triageSimInKev, setTriageSimInKev] = React.useState(true);
  const [triageSimAssets, setTriageSimAssets] = React.useState(18);
  const [triageSimHasEol, setTriageSimHasEol] = React.useState(false);
  const [triageSimSlaDays, setTriageSimSlaDays] = React.useState(4);
  const [triageSimMissingOwner, setTriageSimMissingOwner] = React.useState(false);
  const [triageSimPatchGap, setTriageSimPatchGap] = React.useState(false);

  // Findings Score — add-column form state
  const [newColTable, setNewColTable] = React.useState('VULNERABILITY');
  const [newColColumn, setNewColColumn] = React.useState('severity');
  // Findings Score — simulator selected values (key: "TABLE:column")
  const [simFindingsValues, setSimFindingsValues] = React.useState<Record<string, string>>({});
  // Findings Score — recompute state
  const [recomputeInProgress, setRecomputeInProgress] = React.useState(false);
  const [recomputeMessage, setRecomputeMessage] = React.useState('');

  const policyValidationErrors = React.useMemo(
    () => (policy == null ? [] : validateRiskPolicy(policy)),
    [policy]
  );

  const parsedFindingsColumns = React.useMemo((): FindingsScoreColumn[] => {
    try {
      const parsed = JSON.parse(policy?.findingsScoreConfig ?? '[]');
      if (!Array.isArray(parsed)) return [];
      return (parsed as FindingsScoreColumn[]).map((col) => {
        const colType = getColumnDataType(col.table, col.column);
        return {
          ...col,
          values: col.values.map((v) => ({
            ...v,
            operator: v.operator ?? defaultOperatorForType(colType),
            // Boolean selects have no blank option; if value was saved as '' (before
            // the fix), default it to 'true' so existing conditions evaluate correctly.
            value: (v.value === '' && colType === 'boolean') ? 'true' : v.value,
          })),
        };
      });
    } catch {
      return [];
    }
  }, [policy?.findingsScoreConfig]);

  // Each column contributes its maximum matched weight to the total
  const totalFindingsWeight = React.useMemo(
    () => parsedFindingsColumns.reduce((sum, col) => {
      if (col.values.length === 0) return sum;
      return sum + Math.max(...col.values.map((v) => v.weight));
    }, 0),
    [parsedFindingsColumns]
  );

  const saveFindingsColumns = (cols: FindingsScoreColumn[]): void => {
    updatePolicy('findingsScoreConfig', JSON.stringify(cols));
  };

  const addFindingsColumn = (): void => {
    if (!policy || parsedFindingsColumns.length >= 10) return;
    if (parsedFindingsColumns.some((c) => c.table === newColTable && c.column === newColColumn)) return;
    const colType = getColumnDataType(newColTable, newColColumn);
    const defaultOp = defaultOperatorForType(colType);
    const defaultVal = colType === 'boolean' ? 'true' : '';
    saveFindingsColumns([...parsedFindingsColumns, { table: newColTable, column: newColColumn, values: [{ operator: defaultOp, value: defaultVal, weight: 0 }] }]);
  };

  const removeFindingsColumn = (ci: number): void => {
    saveFindingsColumns(parsedFindingsColumns.filter((_, i) => i !== ci));
  };

  const addValueToColumn = (ci: number): void => {
    const col = parsedFindingsColumns[ci];
    const colType = getColumnDataType(col.table, col.column);
    const defaultOp = defaultOperatorForType(colType);
    const defaultVal = colType === 'boolean' ? 'true' : '';
    saveFindingsColumns(parsedFindingsColumns.map((c, i) =>
      i === ci ? { ...c, values: [...c.values, { operator: defaultOp, value: defaultVal, weight: 0 }] } : c
    ));
  };

  const removeValueFromColumn = (ci: number, vi: number): void => {
    saveFindingsColumns(
      parsedFindingsColumns
        .map((col, i) => i === ci ? { ...col, values: col.values.filter((_, j) => j !== vi) } : col)
        .filter((col) => col.values.length > 0)
    );
  };

  const updateValueInColumn = (
    ci: number, vi: number,
    field: 'operator' | 'value' | 'operator2' | 'value2' | 'weight',
    val: string | number
  ): void => {
    saveFindingsColumns(parsedFindingsColumns.map((col, i) =>
      i === ci ? { ...col, values: col.values.map((v, j) => j === vi ? { ...v, [field]: val } : v) } : col
    ));
  };

  const addSecondBound = (ci: number, vi: number): void => {
    const _col = parsedFindingsColumns[ci];
    saveFindingsColumns(parsedFindingsColumns.map((c, i) =>
      i === ci ? {
        ...c, values: c.values.map((v, j) => j === vi
          ? { ...v, operator2: '<=', value2: '' }
          : v)
      } : c
    ));
  };

  const removeSecondBound = (ci: number, vi: number): void => {
    saveFindingsColumns(parsedFindingsColumns.map((c, i) =>
      i === ci ? {
        ...c, values: c.values.map((v, j) => {
          if (j !== vi) return v;
          const { operator2: _op2, value2: _val2, ...rest } = v;
          return rest;
        })
      } : c
    ));
  };

  // For each column: evaluate all conditions against the sim input, take the max matching weight
  const findingsSimScore = React.useMemo((): number => {
    return parsedFindingsColumns.reduce((sum, col) => {
      const key = `${col.table}:${col.column}`;
      const actual = simFindingsValues[key] ?? '';
      if (actual === '') return sum;
      const colType = getColumnDataType(col.table, col.column);
      const matching = col.values
        .filter((v) => evaluateCondition(v, actual, colType))
        .map((v) => v.weight);
      return sum + (matching.length > 0 ? Math.max(...matching) : 0);
    }, 0);
  }, [parsedFindingsColumns, simFindingsValues]);

  React.useEffect(() => {
    if (riskPolicyQuery.data && !policyDirtyRef.current) {
      // Use functional update so we can preserve findingsScoreConfig from
      // the previous local state if the server response doesn't include it
      // (e.g. backend running pre-V1079 code or column not yet in response).
      setPolicy((prev) => {
        const data = riskPolicyQuery.data!;
        const localFallback =
          prev?.findingsScoreConfig ??
          localStorage.getItem('findings-score-config') ??
          DEFAULT_FINDINGS_SCORE_CONFIG_JSON;
        const merged: RiskPolicy = {
          ...data,
          findingsScoreConfig: data.findingsScoreConfig ?? localFallback,
        };
        return applyTriageDefaults(merged);
      });
    }
  }, [riskPolicyQuery.data]);

  // A failed list load is an error with Retry, never "No ownership rules defined yet".
  const loadOwnershipRules = React.useCallback(() => {
    setOwnershipLoading(true);
    setOwnershipLoadError(false);
    api.listOwnershipRules()
      .then((rules) => setOwnershipRules(rules))
      .catch(() => { setOwnershipRules([]); setOwnershipLoadError(true); })
      .finally(() => setOwnershipLoading(false));
  }, []);

  React.useEffect(() => {
    loadOwnershipRules();

    api.listAssignmentGroups()
      .then((groups) => setOwnershipGroups(Array.from(new Set(groups)).sort((a, b) => a.localeCompare(b))))
      .catch(() => setOwnershipGroups([]));
  }, [loadOwnershipRules]);

  React.useEffect(() => {
    if (!ownershipGroupOpen) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!ownershipGroupRef.current?.contains(event.target as Node)) {
        setOwnershipGroupOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [ownershipGroupOpen]);

  React.useEffect(() => {
    if (!policy && riskPolicyQuery.error) {
      setPolicy(DEFAULT_RISK_POLICY);
      setPolicyMessage('Using local defaults because the backend configuration API is unavailable. Saving will retry the API.');
    }
  }, [policy, riskPolicyQuery.error]);

  const updatePolicy = (key: keyof RiskPolicy, value: number | boolean | string): void => {
    if (!policy) return;
    setPolicy({ ...policy, [key]: value });
    setPolicyDirty(true);
  };

  // Restores the last saved configuration (or the local defaults when the API never answered).
  const discardPolicyChanges = (): void => {
    const data = riskPolicyQuery.data;
    setPolicy(data
      ? applyTriageDefaults({
        ...data,
        findingsScoreConfig: data.findingsScoreConfig ?? localStorage.getItem('findings-score-config') ?? DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
      })
      : DEFAULT_RISK_POLICY);
    setPolicyDirty(false);
    setPolicyMessage('');
  };

  const savePolicy = async (): Promise<void> => {
    if (!policy) return;
    if (policyValidationErrors.length > 0) {
      setPolicyMessage('Fix validation errors before saving.');
      return;
    }
    setPolicySaving(true);
    setPolicyMessage('');
    try {
      const raw = await api.updateRiskPolicy(policy);
      // Preserve findingsScoreConfig from local state when the backend response
      // omits it (backend not yet restarted with the new toResponse() code, or
      // the field is stripped somewhere in the response path).
      const merged: RiskPolicy = {
        ...raw,
        findingsScoreConfig: raw.findingsScoreConfig ?? policy.findingsScoreConfig ?? DEFAULT_FINDINGS_SCORE_CONFIG_JSON,
      };
      const updated = applyTriageDefaults(merged);
      // Persist to localStorage so browser refresh survives even when the
      // backend response omits findingsScoreConfig (pre-restart scenario).
      localStorage.setItem('findings-score-config', updated.findingsScoreConfig ?? DEFAULT_FINDINGS_SCORE_CONFIG_JSON);
      queryClient.setQueryData(['risk-policy'], updated);
      setPolicy(updated);
      setPolicyDirty(false);
      // The risk-policy API does not store the six triage weights (frontend-only fields), so the
      // acknowledgement on that section says so instead of claiming they were saved.
      const triageStored = (raw as unknown as Record<string, unknown>).triageExploitabilityWeight != null;
      setPolicyMessage(activeSection === 'triage' && !triageStored
        ? 'Other settings saved. The server does not store prioritization weights, so they were reset to their defaults.'
        : 'Configuration saved');
    } catch (e) {
      setPolicyMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setPolicySaving(false);
    }
  };

  const recomputeFindingsScores = async (): Promise<void> => {
    setRecomputeInProgress(true);
    setRecomputeMessage('');
    try {
      const result = await api.recomputeFindingsScores();
      setRecomputeMessage(`Done — ${result.updated} finding${result.updated === 1 ? '' : 's'} updated`);
    } catch (e) {
      setRecomputeMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setRecomputeInProgress(false);
    }
  };

  const executeAutoCloseNow = async (): Promise<void> => {
    setAutoCloseExecuting(true);
    setPolicyMessage('');
    try {
      const result = await api.executeAutoCloseNow();
      setPolicyMessage(`Auto-close ran now. ${result.updated} finding${result.updated === 1 ? '' : 's'} updated.`);
      void riskPolicyQuery.refetch();
    } catch (e) {
      setPolicyMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setAutoCloseExecuting(false);
    }
  };

  // Computed triage sim
  const triageSim = React.useMemo(() => {
    if (!policy) return null;
    const exploitSignal = Math.min(1, triageSimEpss * 1.4 + (triageSimInKev ? 0.35 : 0));
    const blastSignal = Math.min(1, triageSimAssets / 40);
    const eolSignal = triageSimHasEol ? 1 : 0;
    const slaSignal = Math.max(0, 1 - triageSimSlaDays / 20);
    const ownerSignal = triageSimMissingOwner ? 1 : 0;
    const patchSignal = triageSimPatchGap ? 1 : 0;

    const exploitC = exploitSignal * policy.triageExploitabilityWeight;
    const blastC = blastSignal * policy.triageBlastRadiusWeight;
    const eolC = eolSignal * policy.triageEolRiskWeight;
    const slaC = slaSignal * policy.triageSlaBreachWeight;
    const ownerC = ownerSignal * policy.triageMissingOwnerBoost;
    const patchC = patchSignal * policy.triagePatchGapBoost;

    const raw = exploitC + blastC + eolC + slaC + ownerC + patchC;
    const normalized = Math.min(10, raw * 1.8);

    const activeReasons: string[] = [];
    if (triageSimInKev) activeReasons.push('Known exploited (KEV)');
    if (triageSimEpss >= 0.5) activeReasons.push(`High EPSS (${(triageSimEpss * 100).toFixed(0)}%)`);
    if (triageSimAssets >= 10) activeReasons.push(`${triageSimAssets} assets affected`);
    if (triageSimHasEol) activeReasons.push('EOL component');
    if (triageSimSlaDays <= 5) activeReasons.push(`SLA breach in ${triageSimSlaDays}d`);
    if (triageSimMissingOwner) activeReasons.push('No owner assigned');
    if (triageSimPatchGap) activeReasons.push('No patch available');

    return { exploitC, blastC, eolC, slaC, ownerC, patchC, raw, normalized, activeReasons };
  }, [
    policy,
    triageSimEpss,
    triageSimInKev,
    triageSimAssets,
    triageSimHasEol,
    triageSimSlaDays,
    triageSimMissingOwner,
    triageSimPatchGap,
  ]);

  if (!policy) {
    return <div className="panel"><p role="status">Loading configuration…</p></div>;
  }

  const sectionErrors = (key: ConfigNavKey): PolicyValidationError[] => {
    const fields = SECTION_FIELDS[key];
    if (!fields) return [];
    return policyValidationErrors.filter((e) => (fields as ReadonlyArray<keyof RiskPolicy>).includes(e.field));
  };

  // Plain render helper — NOT a component, so React never sees a type change
  // across renders (avoids the inner-component unmount/remount anti-pattern).
  const renderSaveRow = (sectionKey: ConfigNavKey) => {
    const errs = sectionErrors(sectionKey);
    return (
      <>
        {errs.length > 0 && (
          <div className="notice error" style={{ marginTop: 12 }}>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {errs.map((e) => <li key={e.field}>{e.message}</li>)}
            </ul>
          </div>
        )}
        <div className="button-row form-submit-row">
          <button
            type="button"
            className="btn btn-primary"
            onClick={savePolicy}
            disabled={!canEditRiskPolicy || policySaving || errs.length > 0}
          >
            {policySaving ? 'Saving…' : 'Save'}
          </button>
          {policyDirty && canEditRiskPolicy && (
            <button type="button" className="btn btn-secondary" onClick={discardPolicyChanges} disabled={policySaving}>
              Discard changes
            </button>
          )}
          {policyDirty && (
            <span className="field-hint config-dirty-cue" style={{ marginLeft: 10, color: 'var(--dp-medium)', fontWeight: 600 }}>
              Unsaved changes
            </span>
          )}
          {!canEditRiskPolicy && (
            <span className="field-hint" style={{ marginLeft: 10 }}>Read-only: your role cannot change this configuration.</span>
          )}
          <span role="status" aria-live="polite">
            {policyMessage && activeSection === sectionKey && (
              <span className="field-hint" style={{ marginLeft: 10, color: /saved|updated|ran now/i.test(policyMessage) ? 'var(--dp-low)' : 'var(--dp-critical)' }}>
                {policyMessage}
              </span>
            )}
          </span>
        </div>
      </>
    );
  };

  // ── Triage section ─────────────────────────────────────────────────────────
  const renderTriage = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          These weights control how the system ranks findings and CVEs{' '}
          <strong>before any investigation starts</strong>. Signals with higher weight push
          matching items to the top of the recommended work queue. Set a signal to{' '}
          <span className="mono">0</span> to ignore it entirely.
        </p>
      </div>

      <div className="notice" role="note" style={{ marginBottom: 12 }}>
        The server does not store these weights yet. Changes here update the simulator below only; prioritization
        elsewhere in the app does not use them, and Save resets them to their defaults.
      </div>

      <div className="triage-signal-list">
        {TRIAGE_SIGNALS.map((sig) => {
          const val = (policy[sig.field] as number) ?? 0;
          const pct = (val / 2) * 100;
          return (
            <div key={sig.field} className="triage-signal-card">
              <div className="triage-signal-top">
                <span className="triage-signal-icon" aria-hidden="true">{sig.icon}</span>
                <div className="triage-signal-meta">
                  <div className="triage-signal-name">{sig.label}</div>
                  <div className="triage-signal-reason">{sig.businessReason}</div>
                  <div className="triage-urgency-tag" style={{ marginTop: 5 }}>
                    Example signal: {sig.urgencyTag}
                  </div>
                </div>
              </div>
              <div className="triage-weight-row">
                <span className="triage-weight-label">Off</span>
                <div style={{ flex: 1, position: 'relative' }}>
                  <input
                    type="range"
                    className="triage-weight-slider"
                    min={0}
                    max={2}
                    step={0.1}
                    value={val}
                    onChange={(e) => updatePolicy(sig.field, Number(e.target.value))}
                    aria-label={`${sig.label} weight`}
                  />
                  <div
                    className="triage-slider-track-fill"
                    style={{ width: `${pct}%` }}
                    aria-hidden="true"
                  />
                </div>
                <span className="triage-weight-label">Max</span>
                <span className="triage-weight-value">{val.toFixed(1)}</span>
              </div>
            </div>
          );
        })}
      </div>

      {renderSaveRow("triage")}

      {/* Triage score simulator */}
      <div className="score-sim" style={{ marginTop: 20 }}>
        <div className="score-sim-header">
          Triage Score Simulator — see how a sample finding ranks under your current weights
        </div>
        <div className="score-sim-body">
          <div className="score-sim-inputs">
            <div className="score-sim-input-row">
              <label htmlFor="triage-sim-epss">EPSS score (probability of exploitation, not confirmed)</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.01}
                  value={triageSimEpss}
                  id="triage-sim-epss"
                  onChange={(e) => setTriageSimEpss(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{(triageSimEpss * 100).toFixed(0)}%</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label htmlFor="triage-sim-assets">Assets affected</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={50}
                  step={1}
                  value={triageSimAssets}
                  id="triage-sim-assets"
                  onChange={(e) => setTriageSimAssets(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{triageSimAssets}</span>
              </div>
            </div>
            <div className="score-sim-input-row">
              <label htmlFor="triage-sim-sla-days">Days until SLA breach</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="range"
                  min={0}
                  max={30}
                  step={1}
                  value={triageSimSlaDays}
                  id="triage-sim-sla-days"
                  onChange={(e) => setTriageSimSlaDays(Number(e.target.value))}
                  style={{ flex: 1 }}
                />
                <span className="triage-weight-value">{triageSimSlaDays}d</span>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 4 }}>
              {[
                { label: 'Known exploited (KEV)', val: triageSimInKev, set: setTriageSimInKev },
                { label: 'EOL component', val: triageSimHasEol, set: setTriageSimHasEol },
                { label: 'No owner assigned', val: triageSimMissingOwner, set: setTriageSimMissingOwner },
                { label: 'No patch available', val: triageSimPatchGap, set: setTriageSimPatchGap },
              ].map(({ label, val, set }) => (
                <label
                  key={label}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', cursor: 'pointer', fontWeight: 500 }}
                >
                  <input
                    type="checkbox"
                    checked={val}
                    onChange={(e) => set(e.target.checked)}
                    style={{ accentColor: 'var(--dp-accent)', width: 14, height: 14 }}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>

          {triageSim && (
            <div className="score-sim-result">
              {(() => {
                const { label, color } = scoreSeverityLabel(triageSim.normalized);
                return (
                  <div
                    className="score-sim-badge"
                    style={{ background: `color-mix(in srgb, ${color} 12%, var(--dp-surface-2))`, border: `1px solid color-mix(in srgb, ${color} 30%, var(--dp-border))` }}
                  >
                    <div>
                      <div
                        className="score-sim-badge-number"
                        style={{ color }}
                      >
                        {triageSim.normalized.toFixed(1)}
                      </div>
                      <div className="score-sim-badge-label" style={{ color }}>
                        {label} Triage Priority
                      </div>
                    </div>
                  </div>
                );
              })()}

              {triageSim.activeReasons.length > 0 && (
                <div>
                  <div style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--dp-text-2)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Active urgency signals
                  </div>
                  <div className="triage-urgency-signals">
                    {triageSim.activeReasons.map((r) => (
                      <span key={r} className="triage-urgency-tag">{r}</span>
                    ))}
                  </div>
                </div>
              )}

              <div className="score-breakdown-list">
                {[
                  { label: 'Exploitability', val: triageSim.exploitC, color: 'var(--dp-critical)' },
                  { label: 'Blast Radius', val: triageSim.blastC, color: 'var(--dp-high)' },
                  { label: 'EOL Risk', val: triageSim.eolC, color: 'var(--dp-medium)' },
                  { label: 'SLA Breach', val: triageSim.slaC, color: 'var(--dp-accent)' },
                  { label: 'Missing Owner', val: triageSim.ownerC, color: 'var(--dp-text-2)' },
                  { label: 'Patch Gap', val: triageSim.patchC, color: 'var(--dp-text-2)' },
                ].map(({ label, val, color }) => (
                  <div key={label} className="score-breakdown-row">
                    <span className="score-breakdown-label">{label}</span>
                    <div className="score-breakdown-bar-bg">
                      <div
                        className="score-breakdown-bar-fill"
                        style={{
                          width: `${Math.min(100, (val / Math.max(triageSim.raw, 0.01)) * 100)}%`,
                          background: color,
                        }}
                      />
                    </div>
                    <span className="score-breakdown-value">{fmt2(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // ── Risk Score section ─────────────────────────────────────────────────────
  // ── SLA section ────────────────────────────────────────────────────────────
  // The matrix wraps instead of using fixed minimum column widths, so it never widens the page
  // (the 768px document overflow). Each field names its tier and unit.
  const slaTiers: Array<{
    tier: string;
    thresholdLabel: string;
    thresholdField?: 'criticalThreshold' | 'highThreshold';
    fixedBoundary?: string;
    daysField: 'criticalSlaDays' | 'highSlaDays' | 'mediumSlaDays' | 'lowSlaDays';
  }> = [
    { tier: 'Critical Risk', thresholdLabel: `Score ≥ ${policy.criticalThreshold} → Critical`, thresholdField: 'criticalThreshold', daysField: 'criticalSlaDays' },
    { tier: 'High Risk', thresholdLabel: `Score ≥ ${policy.highThreshold} → High`, thresholdField: 'highThreshold', daysField: 'highSlaDays' },
    { tier: 'Medium Risk', thresholdLabel: 'Score ≥ 4.0 → Medium', fixedBoundary: 'Fixed tier boundary at 4.0', daysField: 'mediumSlaDays' },
    { tier: 'Low Risk', thresholdLabel: 'Score < 4.0 → Low', fixedBoundary: 'Fixed tier boundary below 4.0', daysField: 'lowSlaDays' },
  ];
  const exampleDue = new Date(Date.now() + policy.criticalSlaDays * 86_400_000);

  const renderSla = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          Sets the remediation deadline for each risk tier. The tier is determined by the
          finding's risk score (0–10), computed from the Findings Score configuration.
        </p>
      </div>

      <div style={{ marginBottom: 8, minWidth: 0 }}>
        <div className="config-subsection-label">Risk Tier SLA Matrix</div>
        <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 12 }}>
          Configure the score threshold and remediation deadline on the same row for each tier. A finding
          whose score is at or above a tier's minimum falls in that tier; the High minimum cannot exceed the Critical minimum.
        </p>
        <div style={{ display: 'grid', gap: 12 }}>
          {slaTiers.map((row) => (
            <fieldset
              key={row.tier}
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))',
                gap: 16,
                alignItems: 'start',
                minWidth: 0,
                margin: 0,
                padding: '14px 16px',
                border: '1px solid var(--dp-border)',
                borderRadius: 12,
                background: 'var(--dp-surface)',
              }}
            >
              <legend className="ui2-sr-only">{row.tier}</legend>
              <div>
                <div style={{ fontWeight: 700, color: 'var(--dp-text)', marginBottom: 6 }}>{row.tier}</div>
                <div className="field-hint">{row.thresholdLabel}</div>
              </div>
              {row.thresholdField ? (
                <label style={{ display: 'grid', gap: 6, margin: 0 }}>
                  <span className="field-hint">Minimum score (0–10)</span>
                  <input
                    type="number"
                    step="0.1"
                    min={0}
                    max={10}
                    aria-label={`${row.tier} minimum score (0–10)`}
                    value={policy[row.thresholdField]}
                    onChange={(e) => updatePolicy(row.thresholdField!, Number(e.target.value))}
                  />
                </label>
              ) : (
                <div className="field-hint">{row.fixedBoundary}</div>
              )}
              <label style={{ display: 'grid', gap: 6, margin: 0 }}>
                <span className="field-hint">Remediate within (days, 0–365)</span>
                <input
                  type="number"
                  min={0}
                  max={365}
                  aria-label={`${row.tier} remediate within (days, 0–365)`}
                  value={policy[row.daysField]}
                  onChange={(e) => updatePolicy(row.daysField, Number(e.target.value))}
                />
              </label>
              <div className="field-hint" style={{ alignSelf: 'center' }}>
                Remediate within {policy[row.daysField]} day{policy[row.daysField] === 1 ? '' : 's'}
              </div>
            </fieldset>
          ))}
        </div>
        <p className="field-hint" style={{ marginTop: 12 }}>
          Example: with these values, a Critical Risk finding detected today is due within {policy.criticalSlaDays} day
          {policy.criticalSlaDays === 1 ? '' : 's'} (by {Number.isNaN(exampleDue.getTime()) ? '—' : exampleDue.toLocaleDateString()}), before any asset-criticality adjustment.
        </p>
      </div>

      {renderSaveRow("sla")}
    </div>
  );

  // ── Automation section ─────────────────────────────────────────────────────
  const renderAutomation = () => (
    <div className="config-section-body">
      <div style={{ border: '1px solid var(--dp-border)', borderRadius: 8, background: 'var(--dp-surface)', padding: '14px 16px', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 13, fontWeight: 600 }}>Auto Close</span>
          <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: policy.autoCloseEnabled ? 'color-mix(in srgb, var(--dp-low) 15%, transparent)' : 'var(--dp-surface-2)', color: policy.autoCloseEnabled ? 'var(--dp-low)' : 'var(--dp-text-2)', border: `1px solid ${policy.autoCloseEnabled ? 'color-mix(in srgb, var(--dp-low) 30%, transparent)' : 'var(--dp-border)'}` }}>
            {policy.autoCloseEnabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="form-grid ingestion-grid" style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 12, color: 'var(--dp-text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            Enable Auto Close
            <select
              style={{ padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)' }}
              value={policy.autoCloseEnabled ? 'true' : 'false'}
              onChange={(e) => updatePolicy('autoCloseEnabled', e.target.value === 'true')}
            >
              <option value="false">Disabled</option>
              <option value="true">Enabled</option>
            </select>
          </label>
          <label style={{ fontSize: 12, color: 'var(--dp-text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            Asset Scope (optional)
            <input
              style={{ padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)' }}
              value={policy.autoCloseAssetIdentifier ?? ''}
              onChange={(e) => updatePolicy('autoCloseAssetIdentifier', e.target.value)}
              placeholder="Blank applies to all assets"
            />
          </label>
          <label style={{ fontSize: 12, color: 'var(--dp-text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            Run Every (days)
            <input
              type="number" min={1} max={365}
              style={{ padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)' }}
              value={policy.autoCloseRunIntervalDays}
              onChange={(e) => updatePolicy('autoCloseRunIntervalDays', Number(e.target.value))}
            />
          </label>
          <label style={{ fontSize: 12, color: 'var(--dp-text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            Grace Period (days)
            <input
              type="number" min={0} max={365}
              style={{ padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)' }}
              value={policy.autoCloseAfterDays}
              onChange={(e) => updatePolicy('autoCloseAfterDays', Number(e.target.value))}
            />
          </label>
          <label style={{ fontSize: 12, color: 'var(--dp-text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
            Required Missed Scans
            <input
              type="number" min={1} max={10}
              style={{ padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)' }}
              value={policy.autoCloseRequiredConsecutiveMisses}
              onChange={(e) => updatePolicy('autoCloseRequiredConsecutiveMisses', Number(e.target.value))}
            />
          </label>
        </div>

        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--dp-text-2)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          Lifecycle Triggers
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {([
            { key: 'autoCloseNotObservedEnabled' as const, label: 'Not observed in latest scans', checked: policy.autoCloseNotObservedEnabled },
            { key: 'autoCloseComponentRemovedEnabled' as const, label: 'Component removed or inactive', checked: policy.autoCloseComponentRemovedEnabled },
            { key: 'autoCloseAssetRetiredEnabled' as const, label: 'Asset retired or inactive', checked: policy.autoCloseAssetRetiredEnabled },
            { key: 'autoCloseSourceDisabledEnabled' as const, label: 'Source disabled', checked: policy.autoCloseSourceDisabledEnabled },
          ]).map(({ key, label, checked }) => (
            <button
              key={key}
              type="button"
              onClick={() => updatePolicy(key, !checked)}
              disabled={!canEditRiskPolicy}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 12px', borderRadius: 20, fontSize: 12, fontWeight: 500,
                cursor: canEditRiskPolicy ? 'pointer' : 'default',
                border: `1px solid ${checked ? 'color-mix(in srgb, var(--dp-accent) 40%, transparent)' : 'var(--dp-border)'}`,
                background: checked ? 'color-mix(in srgb, var(--dp-accent) 10%, var(--dp-surface))' : 'var(--dp-surface)',
                color: checked ? 'var(--dp-accent)' : 'var(--dp-text-2)',
                transition: 'border-color 0.12s, background 0.12s, color 0.12s',
              }}
            >
              <span style={{ fontSize: 10, opacity: checked ? 1 : 0.5 }}>{checked ? '●' : '○'}</span>
              {label}
            </button>
          ))}
        </div>

        <div className="inline-note" style={{ marginTop: 12 }}>
          Open findings are moved to <span className="mono">AUTO_CLOSED</span> only when an enabled lifecycle trigger matches.
          Suppressed or manually closed findings are not auto-closed.
        </div>

        <div style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '4px 12px', fontSize: 12 }}
            onClick={() => void executeAutoCloseNow()}
            disabled={!canEditRiskPolicy || policySaving || autoCloseExecuting}
          >
            {autoCloseExecuting ? 'Executing…' : 'Execute Now'}
          </button>
          {policyDirty && (
            <span className="field-hint" style={{ marginLeft: 10 }}>
              Execute Now uses the saved settings, not your unsaved changes.
            </span>
          )}
        </div>
      </div>

      {renderSaveRow("automation")}
    </div>
  );

  // ── Ownership section ─────────────────────────────────────────────────────
  const openOwnershipCreate = () => {
    setOwnershipForm(blankOwnershipRuleForm());
    setOwnershipEditingId(null);
    setOwnershipMessage('');
    setOwnershipGroupOpen(false);
    setOwnershipShowForm(true);
  };

  const openOwnershipEdit = (rule: OwnershipRule) => {
    setOwnershipForm({
      ...parseOwnershipRuleCondition(rule.condition),
      name: rule.name,
      userGroup: rule.userGroup,
    });
    setOwnershipEditingId(rule.id);
    setOwnershipMessage('');
    setOwnershipGroupOpen(false);
    setOwnershipShowForm(true);
  };

  const cancelOwnershipForm = () => {
    setOwnershipShowForm(false);
    setOwnershipEditingId(null);
    setOwnershipMessage('');
    setOwnershipGroupOpen(false);
  };

  const saveOwnershipRule = () => {
    if (!ownershipForm.name.trim()) {
      setOwnershipMessage('Name is required.');
      return;
    }
    if (ownershipForm.conditions.length === 0 || ownershipForm.conditions.every((row) => !row.value.trim())) {
      setOwnershipMessage('At least one condition value is required.');
      return;
    }
    if (!ownershipForm.userGroup.trim()) {
      setOwnershipMessage('User group is required.');
      return;
    }

    const condition = JSON.stringify({
      logic: ownershipForm.conditionLogic,
      conditions: ownershipForm.conditions
        .map((row) => ({ table: row.table, column: row.column, operator: row.operator, value: row.value }))
        .filter((row) => row.value.trim().length > 0),
    });
    const payload = { name: ownershipForm.name.trim(), condition, userGroup: ownershipForm.userGroup.trim() };

    const apiCall = ownershipEditingId
      ? api.updateOwnershipRule(ownershipEditingId, payload)
      : api.createOwnershipRule(payload);

    apiCall
      .then((saved) => {
        setOwnershipRules((prev) =>
          ownershipEditingId
            ? prev.map((r) => (r.id === ownershipEditingId ? saved : r))
            : [...prev, saved]
        );
        setOwnershipMessage(ownershipEditingId ? 'Ownership rule saved.' : 'Ownership rule created.');
        setOwnershipShowForm(false);
        setOwnershipEditingId(null);
        setOwnershipGroupOpen(false);
      })
      .catch(() => setOwnershipMessage('Failed to save ownership rule.'));
  };

  const addOwnershipCondition = () => {
    setOwnershipForm((current) => ({
      ...current,
      conditions: [...current.conditions, { table: 'ASSET', column: 'owner', operator: '=', value: '' }],
    }));
  };

  const updateOwnershipCondition = (index: number, field: keyof OwnershipConditionRow, value: string) => {
    setOwnershipForm((current) => ({
      ...current,
      conditions: current.conditions.map((row, rowIndex) => {
        if (rowIndex !== index) return row;
        const updated = { ...row, [field]: value } as OwnershipConditionRow;
        if (field === 'table') {
          const columns = FINDINGS_SCORE_COLUMNS[value] ?? [];
          updated.column = columns[0]?.value ?? 'owner';
          updated.operator = '=';
          updated.value = '';
        }
        if (field === 'column') {
          const colType = getColumnDataType(row.table, value);
          updated.operator = defaultOperatorForType(colType);
          updated.value = '';
        }
        return updated;
      }),
    }));
  };

  const removeOwnershipCondition = (index: number) => {
    setOwnershipForm((current) => ({
      ...current,
      conditions: current.conditions.length > 1
        ? current.conditions.filter((_, rowIndex) => rowIndex !== index)
        : current.conditions,
    }));
  };

  const filteredOwnershipGroups = ownershipGroups.filter((group) =>
    group.toLowerCase().includes(ownershipForm.userGroup.trim().toLowerCase()),
  );

  const deleteOwnershipRule = (id: string) => {
    setOwnershipDeleteError('');
    setOwnershipDeleteId(id);
  };

  // The dialog stays open (and names the failure) when the delete is rejected.
  const confirmDeleteOwnershipRule = () => {
    const id = ownershipDeleteId;
    if (!id) return;
    setOwnershipDeleting(true);
    setOwnershipDeleteError('');
    api.deleteOwnershipRule(id)
      .then(() => {
        setOwnershipRules((prev) => prev.filter((r) => r.id !== id));
        if (ownershipEditingId === id) {
          cancelOwnershipForm();
        }
        setOwnershipDeleteId(null);
        setOwnershipMessage('Ownership rule deleted.');
      })
      .catch(() => setOwnershipDeleteError('The ownership rule could not be deleted. Try again.'))
      .finally(() => setOwnershipDeleting(false));
  };

  const executeOwnershipRule = (id: string) => {
    setOwnershipExecutingId(id);
    setOwnershipMessage('');
    api.applyOwnershipRule(id)
      .then(({ updated }) => setOwnershipMessage(`Executed: ${updated} finding${updated !== 1 ? 's' : ''} updated.`))
      .catch(() => setOwnershipMessage('Execution failed. Please try again.'))
      .finally(() => setOwnershipExecutingId(null));
  };

  const renderOwnership = () => (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          Define ownership routing rules by <strong>name</strong>, <strong>condition</strong>, and <strong>user group</strong>.
          Use these rules to route work to the correct team when records match the stated condition.
        </p>
      </div>

      {ownershipMessage && (
        <div className="notice" role="status" style={{ marginBottom: 16 }}>
          {ownershipMessage}
        </div>
      )}

      {!ownershipShowForm && (
        <AsyncSection
          state={ownershipLoading ? 'pending' : ownershipLoadError ? 'error' : ownershipRules.length === 0 ? 'empty' : 'ready'}
          loadingLabel="Loading ownership rules…"
          errorMessage="Ownership rules could not be loaded."
          onRetry={loadOwnershipRules}
          emptyMessage="No ownership rules defined yet."
        >
        <div
          className="config-table-scroll"
          role="region"
          aria-label="Ownership rules"
          tabIndex={0}
          style={{ marginBottom: 20, maxWidth: '100%', overflowX: 'auto' }}
        >
          <table style={{ width: '100%', minWidth: 720, borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--dp-border)', color: 'var(--text-2)', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.71rem', letterSpacing: '0.04em' }}>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px 0' }}>Name</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Condition</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>User Group</th>
                <th style={{ textAlign: 'right', padding: '4px 8px 6px' }}>Findings</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Updated</th>
                <th style={{ padding: '4px 0 6px' }} />
              </tr>
            </thead>
            <tbody>
              {ownershipRules.map((rule) => (
                <tr key={rule.id} style={{ borderBottom: '1px solid var(--dp-border)' }}>
                  <td style={{ padding: '10px 8px 10px 0', fontWeight: 600 }}>{rule.name}</td>
                  <td style={{ padding: '10px 8px', color: 'var(--text-2)', whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{formatOwnershipRuleCondition(rule)}</td>
                  <td style={{ padding: '10px 8px', color: 'var(--text-2)' }}>{rule.userGroup}</td>
                  <td style={{ padding: '10px 8px', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{rule.matchedCount}</td>
                  <td style={{ padding: '10px 8px', color: 'var(--text-2)' }}>{formatInstant(rule.updatedAt)}</td>
                  <td style={{ padding: '10px 0', whiteSpace: 'nowrap', textAlign: 'right' }}>
                    <button type="button" className="btn-link" style={{ fontSize: '0.78rem', marginRight: 8 }} onClick={() => openOwnershipEdit(rule)}>Edit</button>
                    <button type="button" className="btn-link" style={{ fontSize: '0.78rem', color: 'var(--dp-critical)', marginRight: 8 }} onClick={() => deleteOwnershipRule(rule.id)}>Delete</button>
                    <button
                      type="button"
                      className="btn-link"
                      style={{ fontSize: '0.78rem', color: 'var(--dp-accent)' }}
                      disabled={ownershipExecutingId === rule.id}
                      onClick={() => executeOwnershipRule(rule.id)}
                    >
                      {ownershipExecutingId === rule.id ? 'Running…' : 'Execute Now'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </AsyncSection>
      )}

      {ownershipShowForm ? (
        <div style={{ background: 'var(--dp-surface-2)', border: '1px solid var(--dp-border)', borderRadius: 6, padding: 16, marginBottom: 16 }}>
          <div className="form-grid ingestion-grid" style={{ marginBottom: 12 }}>
            <label>Name *
              <input
                value={ownershipForm.name}
                onChange={(e) => setOwnershipForm((current) => ({ ...current, name: e.target.value }))}
                placeholder="e.g. Route internet-facing findings"
              />
            </label>
            <label ref={ownershipGroupRef} style={{ position: 'relative' }}>User Group *
              <input
                value={ownershipForm.userGroup}
                onFocus={() => setOwnershipGroupOpen(true)}
                onClick={() => setOwnershipGroupOpen(true)}
                onChange={(e) => {
                  setOwnershipForm((current) => ({ ...current, userGroup: e.target.value }));
                  setOwnershipGroupOpen(true);
                }}
                placeholder="Choose user group"
                autoComplete="off"
              />
              {ownershipGroupOpen && (
                <div
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 4px)',
                    left: 0,
                    right: 0,
                    zIndex: 30,
                    maxHeight: 220,
                    overflowY: 'auto',
                    overscrollBehavior: 'contain',
                    background: 'var(--dp-bg)',
                    border: '1px solid var(--dp-border)',
                    borderRadius: 8,
                    boxShadow: '0 18px 36px rgba(15, 23, 42, 0.12)',
                    padding: 4,
                  }}
                >
                  {filteredOwnershipGroups.length > 0 ? (
                    filteredOwnershipGroups.map((group) => (
                      <button
                        key={group}
                        type="button"
                        onClick={() => {
                          setOwnershipForm((current) => ({ ...current, userGroup: group }));
                          setOwnershipGroupOpen(false);
                        }}
                        style={{
                          width: '100%',
                          textAlign: 'left',
                          border: 'none',
                          background: 'transparent',
                          padding: '10px 12px',
                          borderRadius: 6,
                          cursor: 'pointer',
                          fontSize: '0.88rem',
                          fontWeight: 600,
                        }}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(76, 110, 245, 0.08)'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; }}
                      >
                        {group}
                      </button>
                    ))
                  ) : (
                    <div style={{ padding: '10px 12px', color: 'var(--text-2)', fontSize: '0.82rem' }}>
                      No matching groups
                    </div>
                  )}
                </div>
              )}
            </label>
          </div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>Conditions</span>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-2)' }}>Route when</span>
              <select
                value={ownershipForm.conditionLogic}
                style={{ width: 100, margin: 0, fontSize: '0.8rem' }}
                onChange={(e) => setOwnershipForm((current) => ({ ...current, conditionLogic: e.target.value as 'AND' | 'OR' }))}
              >
                <option value="AND">ALL (AND)</option>
                <option value="OR">ANY (OR)</option>
              </select>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-2)' }}>of these conditions match:</span>
            </div>

            <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '40px 130px 160px 110px minmax(120px, 1fr) 22px',
                  gap: 8,
                  padding: '0 10px',
                  color: 'var(--text-2)',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                <span>Logic</span>
                <span>Table</span>
                <span>Column</span>
                <span>Operator</span>
                <span>Value</span>
                <span />
              </div>
              {ownershipForm.conditions.map((cond, index) => {
                const columnType = getColumnDataType(cond.table, cond.column);
                const operators = getOperatorsForType(columnType);
                const isBoolean = columnType === 'boolean';
                const isNumeric = columnType === 'numeric';
                return (
                  <div
                    key={`${index}-${cond.table}-${cond.column}`}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '40px 130px 160px 110px minmax(120px, 1fr) 22px',
                      gap: 8,
                      alignItems: 'center',
                      background: 'var(--panel-bg, var(--dp-bg))',
                      border: '1px solid var(--dp-border)',
                      borderRadius: 6,
                      padding: '8px 10px',
                    }}
                  >
                    <span style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--dp-accent)', minWidth: 30, textAlign: 'center' }}>
                      {index > 0 ? ownershipForm.conditionLogic : ''}
                    </span>
                    <select
                      value={cond.table}
                      style={{ width: '100%', margin: 0, fontSize: '0.8rem' }}
                      onChange={(e) => updateOwnershipCondition(index, 'table', e.target.value)}
                    >
                      {FINDINGS_SCORE_TABLES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                    <select
                      value={cond.column}
                      style={{ width: '100%', margin: 0, fontSize: '0.8rem' }}
                      onChange={(e) => updateOwnershipCondition(index, 'column', e.target.value)}
                    >
                      {(FINDINGS_SCORE_COLUMNS[cond.table] ?? []).map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                    <select
                      value={cond.operator}
                      style={{ width: '100%', margin: 0, fontSize: '0.8rem' }}
                      onChange={(e) => updateOwnershipCondition(index, 'operator', e.target.value)}
                    >
                      {operators.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
                    </select>
                    {isBoolean ? (
                      <select
                        value={cond.value}
                        style={{ width: '100%', margin: 0, fontSize: '0.8rem' }}
                        onChange={(e) => updateOwnershipCondition(index, 'value', e.target.value)}
                      >
                        <option value="true">true</option>
                        <option value="false">false</option>
                      </select>
                    ) : (
                      <input
                        type={isNumeric ? 'number' : 'text'}
                        placeholder="value"
                        value={cond.value}
                        onChange={(e) => updateOwnershipCondition(index, 'value', e.target.value)}
                        style={{ width: '100%', border: '1px solid var(--dp-border)', borderRadius: 4, background: 'var(--panel-bg, var(--dp-bg))', fontSize: '0.8rem', padding: '7px 10px' }}
                      />
                    )}
                    {ownershipForm.conditions.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeOwnershipCondition(index)}
                        style={{ border: 'none', background: 'none', color: 'var(--dp-critical)', cursor: 'pointer', fontSize: '1rem', lineHeight: 1, padding: '0 2px' }}
                      >
                        ×
                      </button>
                    )}
                  </div>
                );
              })}
            </div>

            <button type="button" className="btn-link" onClick={addOwnershipCondition} style={{ fontSize: '0.8rem', marginTop: 6 }}>
              + New condition
            </button>
          </div>
          <div className="button-row form-submit-row">
            <button type="button" className="btn btn-primary" onClick={saveOwnershipRule} disabled={!canEditRiskPolicy}>
              {ownershipEditingId ? 'Update Rule' : 'Create Rule'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={cancelOwnershipForm}>Close</button>
          </div>
        </div>
      ) : canEditRiskPolicy && !ownershipLoading && (
        <div className="button-row form-submit-row">
          <button type="button" className="btn btn-secondary" onClick={openOwnershipCreate}>
            + New Rule
          </button>
        </div>
      )}
    </div>
  );

  // ── Dev tools section ──────────────────────────────────────────────────────
  // ── Findings Score section ─────────────────────────────────────────────────
  const renderFindingsScore = () => {
    const weightOk = parsedFindingsColumns.length === 0 || Math.abs(totalFindingsWeight - 1) < 0.001;
    const hdr: React.CSSProperties = { color: 'var(--text-2)', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.71rem', letterSpacing: '0.04em' };
    const grid = '120px 140px 1fr 70px';

    return (
      <div className="config-section-body">
        <div className="config-section-intro">
          <p>
            Configure up to <strong>10 columns</strong>. For each column, add one or more
            condition → weight pairs (weight 0–1). The column contributes its{' '}
            <strong>highest matching weight</strong> to the total; all column contributions
            must sum to <strong>1.0</strong>. Score is scaled to 0–10.
          </p>
        </div>

        {parsedFindingsColumns.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            {/* Header row */}
            <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 8, padding: '4px 0 6px', borderBottom: '2px solid var(--dp-border)' }}>
              <span style={hdr}>Table</span>
              <span style={hdr}>Column</span>
              <span style={hdr}>Condition &amp; Weight</span>
              <span />
            </div>

            {parsedFindingsColumns.map((col, ci) => {
              const tableLabel = FINDINGS_SCORE_TABLES.find((t) => t.value === col.table)?.label ?? col.table;
              const colLabel = (FINDINGS_SCORE_COLUMNS[col.table] ?? []).find((c) => c.value === col.column)?.label ?? col.column;
              const colType = getColumnDataType(col.table, col.column);
              const operators = getOperatorsForType(colType);
              const isNumeric = colType === 'numeric';
              const isBoolean = colType === 'boolean';

              return (
                <React.Fragment key={ci}>
                  {/* One row per value */}
                  {col.values.map((vw, vi) => (
                    <div key={vi} style={{ display: 'grid', gridTemplateColumns: grid, gap: 8, padding: '6px 0', alignItems: 'center' }}>
                      {/* Table + Column labels — only on first value row */}
                      {vi === 0 ? (
                        <>
                          <span style={{ fontSize: '0.83rem', fontWeight: 600 }}>{tableLabel}</span>
                          <span style={{ fontSize: '0.83rem', color: 'var(--text-2)' }}>{colLabel}</span>
                        </>
                      ) : (
                        <><span /><span /></>
                      )}

                      {/* Condition chip: [op] [val] [AND op2 val2] Weight: [w] [×] */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--dp-surface-2)', border: '1px solid var(--dp-border)', borderRadius: 4, padding: '4px 10px', width: 'fit-content' }}>
                        {/* First bound */}
                        <select
                          value={vw.operator}
                          style={{ minWidth: 100, margin: 0, fontSize: '0.8rem' }}
                          onChange={(e) => updateValueInColumn(ci, vi, 'operator', e.target.value)}
                          disabled={!canEditRiskPolicy}
                        >
                          {operators.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
                        </select>

                        {isBoolean ? (
                          <select
                            value={vw.value}
                            style={{ width: 80, margin: 0, fontSize: '0.8rem' }}
                            onChange={(e) => updateValueInColumn(ci, vi, 'value', e.target.value)}
                            disabled={!canEditRiskPolicy}
                          >
                            <option value="true">true</option>
                            <option value="false">false</option>
                          </select>
                        ) : (
                          <input
                            type={isNumeric ? 'number' : 'text'}
                            placeholder="value"
                            value={vw.value}
                            onChange={(e) => updateValueInColumn(ci, vi, 'value', e.target.value)}
                            style={{ width: 86, border: 'none', borderBottom: '1px solid var(--dp-border)', background: 'transparent', fontSize: '0.8rem', outline: 'none' }}
                            disabled={!canEditRiskPolicy}
                          />
                        )}

                        {/* AND second bound — numeric only */}
                        {isNumeric && (vw.operator2 != null ? (
                          <>
                            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-2)', padding: '0 2px' }}>AND</span>
                            <select
                              value={vw.operator2}
                              style={{ minWidth: 80, margin: 0, fontSize: '0.8rem' }}
                              onChange={(e) => updateValueInColumn(ci, vi, 'operator2', e.target.value)}
                              disabled={!canEditRiskPolicy}
                            >
                              {NUMERIC_OPS.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
                            </select>
                            <input
                              type="number"
                              placeholder="value"
                              value={vw.value2 ?? ''}
                              onChange={(e) => updateValueInColumn(ci, vi, 'value2', e.target.value)}
                              style={{ width: 72, border: 'none', borderBottom: '1px solid var(--dp-border)', background: 'transparent', fontSize: '0.8rem', outline: 'none' }}
                              disabled={!canEditRiskPolicy}
                            />
                            {canEditRiskPolicy && (
                              <button type="button" onClick={() => removeSecondBound(ci, vi)} title="Remove AND condition" style={{ border: 'none', background: 'none', color: 'var(--text-2)', cursor: 'pointer', fontSize: '0.75rem', lineHeight: 1, padding: '0 1px' }}>✕</button>
                            )}
                          </>
                        ) : canEditRiskPolicy && (
                          <button
                            type="button"
                            onClick={() => addSecondBound(ci, vi)}
                            style={{ border: 'none', background: 'none', color: 'var(--dp-accent)', cursor: 'pointer', fontSize: '0.75rem', whiteSpace: 'nowrap', padding: '0 2px' }}
                          >+ and</button>
                        ))}

                        {/* Weight */}
                        <span style={{ color: 'var(--text-2)', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>Weight:</span>
                        <input
                          type="number"
                          min={0}
                          max={1}
                          step={0.05}
                          value={vw.weight}
                          onChange={(e) => updateValueInColumn(ci, vi, 'weight', Math.min(1, Math.max(0, Number(e.target.value))))}
                          style={{ width: 60, padding: '2px 5px', border: '1px solid var(--dp-border)', borderRadius: 3, background: 'var(--panel-bg, var(--dp-bg))', fontSize: '0.8rem', fontWeight: 600 }}
                          disabled={!canEditRiskPolicy}
                        />

                        {canEditRiskPolicy && (
                          <button type="button" onClick={() => removeValueFromColumn(ci, vi)} style={{ border: 'none', background: 'none', color: 'var(--dp-critical)', cursor: 'pointer', fontSize: '1rem', lineHeight: 1, padding: '0 2px' }}>×</button>
                        )}
                      </div>

                      {/* Remove column — only on first value row */}
                      {vi === 0 && canEditRiskPolicy ? (
                        <button type="button" className="btn-link" onClick={() => removeFindingsColumn(ci)} style={{ color: 'var(--dp-critical)', fontSize: '0.78rem' }}>Remove</button>
                      ) : <span />}
                    </div>
                  ))}

                  {/* + value row (below all value rows, no table/col labels) */}
                  <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 8, padding: '2px 0 10px', borderBottom: '1px solid var(--dp-border)' }}>
                    <span /><span />
                    {canEditRiskPolicy && (
                      <button type="button" className="btn-link" onClick={() => addValueToColumn(ci)} style={{ fontSize: '0.78rem', textAlign: 'left' }}>+ value</button>
                    )}
                    <span />
                  </div>
                </React.Fragment>
              );
            })}

            {/* Total weight */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0 0', fontSize: '0.83rem' }}>
              <span style={{ color: 'var(--text-2)' }}>Total weight:</span>
              <span style={{ fontWeight: 700, color: weightOk ? 'var(--dp-low)' : 'var(--dp-medium)' }}>
                {totalFindingsWeight.toFixed(2)}{weightOk ? ' ✓' : ' ⚠ must equal 1.00'}
              </span>
              <span style={{ color: 'var(--text-2)', fontSize: '0.77rem' }}>· {parsedFindingsColumns.length}/10 columns</span>
            </div>
          </div>
        )}

        {/* Add column form */}
        {parsedFindingsColumns.length < 10 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-2)', whiteSpace: 'nowrap' }}>Add column:</span>
            <select
              value={newColTable}
              style={{ width: 140, margin: 0 }}
              onChange={(e) => { setNewColTable(e.target.value); setNewColColumn(FINDINGS_SCORE_COLUMNS[e.target.value]?.[0]?.value ?? ''); }}
              disabled={!canEditRiskPolicy}
            >
              {FINDINGS_SCORE_TABLES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
            <select
              value={newColColumn}
              style={{ width: 180, margin: 0 }}
              onChange={(e) => setNewColColumn(e.target.value)}
              disabled={!canEditRiskPolicy}
            >
              {(FINDINGS_SCORE_COLUMNS[newColTable] ?? []).map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={addFindingsColumn}
              disabled={!canEditRiskPolicy || parsedFindingsColumns.some((c) => c.table === newColTable && c.column === newColColumn)}
              style={{ whiteSpace: 'nowrap' }}
            >
              + Add Column
            </button>
            <span style={{ fontSize: '0.77rem', color: 'var(--text-2)' }}>{parsedFindingsColumns.length}/10</span>
          </div>
        ) : (
          <div className="notice" style={{ marginBottom: 16 }}>Maximum of 10 columns reached.</div>
        )}

        {renderSaveRow('findings-score')}

        <div className="button-row" style={{ marginTop: 8 }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={recomputeFindingsScores}
            disabled={!canEditRiskPolicy || recomputeInProgress}
            title="Recompute risk scores for all open findings using the saved Findings Score config"
          >
            {recomputeInProgress ? 'Recalculating…' : 'Recalculate Findings'}
          </button>
          {policyDirty && (
            <span className="field-hint" style={{ marginLeft: 10 }}>
              Recalculation uses the saved configuration, not your unsaved changes.
            </span>
          )}
          {recomputeMessage && (
            <span className="field-hint" style={{ marginLeft: 10, color: recomputeMessage.includes('updated') ? 'var(--dp-low)' : 'var(--dp-critical)' }}>
              {recomputeMessage}
            </span>
          )}
        </div>

        {/* Simulator */}
        {parsedFindingsColumns.length > 0 && (
          <div className="score-sim" style={{ marginTop: 20 }}>
            <div className="score-sim-header">Findings Score Simulator — preview how conditions evaluate against sample values</div>
            <div className="score-sim-body">
              <div className="score-sim-inputs">
                {parsedFindingsColumns.map((col, ci) => {
                  const colLabel = (FINDINGS_SCORE_COLUMNS[col.table] ?? []).find((c) => c.value === col.column)?.label ?? col.column;
                  const key = `${col.table}:${col.column}`;
                  const colType = getColumnDataType(col.table, col.column);
                  const currentVal = simFindingsValues[key] ?? '';
                  return (
                    <div key={ci} className="score-sim-input-row">
                      <label>{colLabel}</label>
                      {colType === 'boolean' ? (
                        <select value={currentVal} onChange={(e) => setSimFindingsValues((p) => ({ ...p, [key]: e.target.value }))}>
                          <option value="">(not set)</option>
                          <option value="true">true</option>
                          <option value="false">false</option>
                        </select>
                      ) : colType === 'numeric' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <input
                            type="range"
                            min={0}
                            max={col.column === 'epssScore' ? 1 : 10}
                            step={col.column === 'epssScore' ? 0.01 : 0.1}
                            value={currentVal || '0'}
                            onChange={(e) => setSimFindingsValues((p) => ({ ...p, [key]: e.target.value }))}
                            style={{ flex: 1 }}
                          />
                          <span className="triage-weight-value">{currentVal || '0'}</span>
                        </div>
                      ) : (
                        <input
                          type="text"
                          placeholder="enter value to test"
                          value={currentVal}
                          onChange={(e) => setSimFindingsValues((p) => ({ ...p, [key]: e.target.value }))}
                        />
                      )}
                    </div>
                  );
                })}
              </div>

              <div className="score-sim-result">
                {(() => {
                  const score = Math.min(10, findingsSimScore * 10);
                  const { label, color } = scoreSeverityLabel(score);
                  const contributions = parsedFindingsColumns.map((col) => {
                    const key = `${col.table}:${col.column}`;
                    const actual = simFindingsValues[key] ?? '';
                    const colType = getColumnDataType(col.table, col.column);
                    const matching = col.values
                      .filter((v) => evaluateCondition(v, actual, colType))
                      .map((v) => v.weight);
                    const colLabel = (FINDINGS_SCORE_COLUMNS[col.table] ?? []).find((c) => c.value === col.column)?.label ?? col.column;
                    return { label: colLabel, val: matching.length > 0 ? Math.max(...matching) : 0 };
                  });
                  const maxVal = Math.max(...contributions.map((c) => c.val), 0.01);
                  return (
                    <>
                      <div
                        className="score-sim-badge"
                        style={{ background: `color-mix(in srgb, ${color} 12%, var(--dp-surface-2))`, border: `1px solid color-mix(in srgb, ${color} 30%, var(--dp-border))` }}
                      >
                        <div>
                          <div className="score-sim-badge-number" style={{ color }}>{score.toFixed(1)}</div>
                          <div className="score-sim-badge-label" style={{ color }}>Findings Score — {label}</div>
                        </div>
                      </div>
                      <div className="score-breakdown-list">
                        {contributions.map(({ label: lbl, val }) => (
                          <div key={lbl} className="score-breakdown-row">
                            <span className="score-breakdown-label">{lbl}</span>
                            <div className="score-breakdown-bar-bg">
                              <div className="score-breakdown-bar-fill" style={{ width: `${Math.min(100, (val / maxVal) * 100)}%`, background: 'var(--dp-accent)' }} />
                            </div>
                            <span className="score-breakdown-value">{val.toFixed(2)}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  );
                })()}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // ── Suppress section ──────────────────────────────────────────────────────
  const renderSuppress = () => (
    <SuppressionSection canEdit={canEditRiskPolicy} />
  );

  const renderAutoFindings = () => (
    <AutoFindingRulesSection canEdit={canEditRiskPolicy} />
  );

  const SECTION_TITLES: Record<ConfigNavKey, { title: string; description: string }> = {
    triage: {
      title: 'S.AI Prioritization',
      description:
        'Configure how urgency signals are weighted when the S.AI engine ranks findings and CVEs before investigation starts.',
    },
    sla: {
      title: 'SLA & Remediation',
      description:
        'Set remediation deadlines per risk tier and apply asset criticality multipliers.',
    },
    automation: {
      title: 'Workflow Automation',
      description:
        'Control when stale findings are automatically closed.',
    },
    ownership: {
      title: 'Ownership',
      description:
        'Route records to the right user group using rule-based ownership conditions.',
    },
    'findings-score': {
      title: 'Findings Score',
      description:
        'Define custom attribute-based scoring rules that boost a finding\'s risk score when specific values are matched.',
    },
    suppress: {
      title: 'Suppression Rules',
      description: 'Define rules that suppress CVE or finding records when matching conditions are met.',
    },
    'auto-findings': {
      title: 'Auto Investigation & Findings',
      description: 'Define rules that run investigation first and optionally create findings after the investigation completes.',
    },
  };

  const { title, description } = SECTION_TITLES[activeSection];

  return (
    <div className="panel ui2-connect-family">
      <div className="panel-header">
        {/* The shell renders the route H1; this panel heading sits one level below it. */}
        <h2>Configurations</h2>
        <span className="panel-caption">
          Findings Score, S.AI prioritization, SLA, and workflow automation
        </span>
      </div>

      <div className="config-layout">
        {/* Content */}
        <div className="config-content">
          <div className="config-section-head">
            <div className="config-section-head-text">
              <h2>{title}</h2>
              <p>{description}</p>
            </div>
          </div>

          {/* Stays visible on every section: the values shown are local defaults, not the tenant's saved configuration. */}
          {riskPolicyQuery.error && !riskPolicyQuery.data && ['triage', 'sla', 'automation', 'findings-score'].includes(activeSection) && (
            <div className="notice error" role="alert">
              The saved configuration could not be loaded, so local defaults are shown. Saving will retry the API.{' '}
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => void riskPolicyQuery.refetch()} disabled={riskPolicyQuery.isFetching}>
                {riskPolicyQuery.isFetching ? 'Retrying…' : 'Retry'}
              </button>
            </div>
          )}

          {activeSection === 'triage' && renderTriage()}
          {activeSection === 'sla' && renderSla()}
          {activeSection === 'automation' && renderAutomation()}
          {activeSection === 'ownership' && renderOwnership()}
          {activeSection === 'findings-score' && renderFindingsScore()}
          {activeSection === 'suppress' && renderSuppress()}
          {activeSection === 'auto-findings' && renderAutoFindings()}
        </div>
      </div>

      <ConfirmDialog
        isOpen={ownershipDeleteId != null}
        title="Delete ownership rule?"
        message={(
          <>
            <p>
              This permanently deletes <strong>{ownershipRules.find((rule) => rule.id === ownershipDeleteId)?.name ?? 'this rule'}</strong>.
              It will no longer route matching records.
            </p>
            {ownershipDeleteError && <p className="notice error" role="alert">{ownershipDeleteError}</p>}
          </>
        )}
        confirmLabel="Delete rule"
        busy={ownershipDeleting}
        busyMessage="Deleting ownership rule…"
        onConfirm={confirmDeleteOwnershipRule}
        onCancel={() => { setOwnershipDeleteId(null); setOwnershipDeleteError(''); }}
      />
    </div>
  );
}

// ── SuppressionSection — standalone component (hoisted) ─────────────────────

const ALL_VULN_SOURCES: VulnerabilitySourceSystem[] = ['nvd', 'kev', 'ghsa', 'redhat', 'microsoft', 'euvd', 'jvn', 'advisory', 'epss'];

const VULNERABILITY_SOURCE_COPY: Record<VulnerabilitySourceSystem, { label: string; description: string; badge: string }> = {
  advisory: { label: 'Manual advisories', description: 'Approved advisory imports and their affected product rules.', badge: 'SG' },
  epss: { label: 'EPSS', description: 'Approved exploitation probability enrichment; does not establish applicability.', badge: 'FIRST' },
  nvd: {
    label: 'NVD',
    description: 'National Vulnerability Database — baseline national feed providing broad CVE coverage with CVSS scoring.',
    badge: 'NIST / NVD',
  },
  kev: {
    label: 'KEV',
    description: 'CISA Known Exploited Vulnerabilities — active exploitation context used to prioritize critical findings.',
    badge: 'CISA',
  },
  ghsa: {
    label: 'GHSA',
    description: 'GitHub Security Advisories — ecosystem and package-centric coverage with direct version applicability.',
    badge: 'GitHub',
  },
  redhat: {
    label: 'Red Hat CSAF',
    description: 'Red Hat CSAF/VEX advisories — vendor advisory data for Red Hat and related ecosystems.',
    badge: 'Red Hat',
  },
  microsoft: {
    label: 'Microsoft CSAF',
    description: 'Microsoft CSAF/VEX advisories — Microsoft security updates and applicability statements.',
    badge: 'Microsoft',
  },
  euvd: {
    label: 'EUVD',
    description: 'ENISA European Vulnerability Database — EU-curated vulnerability records with EUVD-to-CVE correlations.',
    badge: 'ENISA',
  },
  jvn: {
    label: 'JVN',
    description: 'Japan Vulnerability Notes — Japanese vulnerability information with JVN-to-CVE cross-references.',
    badge: 'JPCERT/CC',
  },
};

function toSourceFilterRequest(config: VulnerabilitySourceFilterConfig): VulnerabilitySourceFilterConfigRequest {
  return {
    enabledForCorrelation: config.enabledForCorrelation ?? true,
    cpeName: config.cpeName,
    isVulnerable: config.isVulnerable,
    hasKev: config.hasKev,
    cvssV3Severity: config.cvssV3Severity,
    cvssV4Severity: config.cvssV4Severity,
    vendorProject: config.vendorProject,
    product: config.product,
    dateAddedFrom: config.dateAddedFrom,
    dateAddedTo: config.dateAddedTo,
    dueDateFrom: config.dueDateFrom,
    dueDateTo: config.dueDateTo,
    knownRansomwareCampaignUse: config.knownRansomwareCampaignUse,
    severity: config.severity,
    cvssScore: config.cvssScore,
    cvss3Score: config.cvss3Score,
  };
}

export function VulnerabilitySourcesSection({ canEdit }: { canEdit: boolean }) {
  const client = useQueryClient();
  const configs = useQuery({ queryKey: ['tenant-intelligence-sources'], queryFn: api.listVulnerabilitySourceFilterConfigs });
  const processing = useQuery({ queryKey: ['tenant-intelligence-processing'], queryFn: intelligenceApi.tenantStatus, refetchInterval: 5000 });
  const toggle = useMutation({ mutationFn: ({ source, enabled }: { source: VulnerabilitySourceSystem; enabled: boolean }) => {
    const config = configs.data?.find((item) => item.sourceSystem === source);
    return api.saveVulnerabilitySourceFilterConfig(source, { ...(config ? toSourceFilterRequest(config) : {}), enabledForCorrelation: enabled });
  }, onSuccess: () => { void client.invalidateQueries({ queryKey: ['tenant-intelligence-sources'] }); void client.invalidateQueries({ queryKey: ['tenant-intelligence-processing'] }); } });
  return <section className="config-section-body">
    <p>Enabled sources automatically evaluate your inventory after publication. Disabling a source retains finding history and analyst decisions.</p>
    {processing.data && <p role="status">Processing: {processing.data.status} · revision {processing.data.completed_revision}/{processing.data.required_revision} · release {processing.data.current_release_id ?? 'Awaiting first publication'}{processing.data.last_error ? ` · ${processing.data.last_error}` : ''}</p>}
    {[configs.error, processing.error, toggle.error].filter(Boolean).map((error, index) => <p role="alert" className="notice error" key={index}>{error instanceof Error ? error.message : 'Request failed'}</p>)}
    {configs.isLoading ? <p>Loading vulnerability sources…</p> : ALL_VULN_SOURCES.map((source) => {
      const enabled = configs.data?.find((config) => config.sourceSystem === source)?.enabledForCorrelation ?? true;
      const copy = VULNERABILITY_SOURCE_COPY[source];
      return <article className="panel" key={source}><h4>{copy.label}</h4><p>{copy.description}</p><button type="button" className="btn btn-secondary" role="switch" aria-checked={enabled} aria-label={`${copy.label} source`} disabled={!canEdit || toggle.isPending} onClick={() => toggle.mutate({ source, enabled: !enabled })}>{enabled ? 'Enabled' : 'Disabled'}</button></article>;
    })}
  </section>;
}

const BLANK_CONDITION: SuppressionCondition = { table: 'VULNERABILITY', column: 'severity', operator: '=', value: '' };

function blankRule(): SuppressionRuleRequest {
  return {
    name: '',
    state: 'DRAFT',
    recordType: 'FINDING',
    conditionsJson: JSON.stringify([BLANK_CONDITION]),
    conditionLogic: 'AND',
    reason: '',
    validFrom: undefined,
    validTo: undefined,
  };
}

function parseConditions(json: string): SuppressionCondition[] {
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) return [{ ...BLANK_CONDITION }];
    return parsed as SuppressionCondition[];
  } catch {
    return [{ ...BLANK_CONDITION }];
  }
}

function formatInstant(iso?: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return iso;
  }
}

function stateBadgeColor(state: string): string {
  switch (state) {
    case 'APPROVED': return 'var(--dp-low)';
    case 'REJECTED': return 'var(--dp-critical)';
    case 'IN_REVIEW': return 'var(--dp-medium)';
    case 'EXPIRED': return 'var(--text-2)';
    default: return 'var(--dp-accent)';
  }
}

function SuppressionSection({ canEdit }: { canEdit: boolean }) {
  const [rules, setRules] = React.useState<SuppressionRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState('');
  const [showForm, setShowForm] = React.useState(false);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [form, setForm] = React.useState<SuppressionRuleRequest>(blankRule());
  const [saving, setSaving] = React.useState(false);
  const [saveMsg, setSaveMsg] = React.useState('');
  const [executeMsg, setExecuteMsg] = React.useState<Record<string, string>>({});
  const [executingId, setExecutingId] = React.useState<string | null>(null);
  const [reopeningAllId, setReopeningAllId] = React.useState<string | null>(null);
  const [deleteId, setDeleteId] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState('');
  const [listMessage, setListMessage] = React.useState('');

  const loadRules = React.useCallback(() => {
    setLoading(true);
    setError('');
    api.listSuppressionRules()
      .then((data) => { setRules(data); setLoading(false); })
      .catch((e) => { setError(e instanceof Error ? e.message : String(e)); setLoading(false); });
  }, []);

  React.useEffect(() => {
    loadRules();
  }, [loadRules]);

  const conditions = parseConditions(form.conditionsJson);

  const setConditions = (next: SuppressionCondition[]) => {
    setForm((f) => ({ ...f, conditionsJson: JSON.stringify(next) }));
  };

  const addCondition = () => setConditions([...conditions, { ...BLANK_CONDITION }]);

  const removeCondition = (i: number) => {
    if (conditions.length <= 1) return;
    setConditions(conditions.filter((_, j) => j !== i));
  };

  const updateCondition = (i: number, field: keyof SuppressionCondition, val: string) => {
    setConditions(conditions.map((c, j) => {
      if (j !== i) return c;
      const updated = { ...c, [field]: val };
      // reset column/operator/value when table changes
      if (field === 'table') {
        updated.column = FINDINGS_SCORE_COLUMNS[val]?.[0]?.value ?? 'severity';
        const colType = getColumnDataType(val, updated.column);
        updated.operator = defaultOperatorForType(colType);
        updated.value = colType === 'boolean' ? 'true' : '';
      }
      if (field === 'column') {
        const colType = getColumnDataType(c.table, val);
        updated.operator = defaultOperatorForType(colType);
        updated.value = colType === 'boolean' ? 'true' : '';
      }
      return updated;
    }));
  };

  const openCreate = () => {
    setForm(blankRule());
    setEditingId(null);
    setSaveMsg('');
    setShowForm(true);
  };

  const executeRule = async (id: string) => {
    setExecutingId(id);
    setExecuteMsg((m) => ({ ...m, [id]: '' }));
    try {
      const result = await api.executeSuppressionRule(id);
      if (result.error) {
        setExecuteMsg((m) => ({ ...m, [id]: result.error! }));
      } else {
        const noun = rules.find(r => r.id === id)?.recordType === 'CVE' ? 'CVE record' : 'finding';
        setExecuteMsg((m) => ({ ...m, [id]: `${result.suppressed} ${noun}${result.suppressed === 1 ? '' : 's'} suppressed` }));
        // Refresh the list to get updated suppressed counts
        const updated = await api.listSuppressionRules();
        setRules(updated);
      }
    } catch (e) {
      setExecuteMsg((m) => ({ ...m, [id]: e instanceof Error ? e.message : String(e) }));
    } finally {
      setExecutingId(null);
    }
  };

  const reopenAll = async (id: string) => {
    setReopeningAllId(id);
    setExecuteMsg((m) => ({ ...m, [id]: '' }));
    try {
      const result = await api.reopenAllByRule(id);
      const noun = rules.find(r => r.id === id)?.recordType === 'CVE' ? 'CVE record' : 'finding';
      setExecuteMsg((m) => ({ ...m, [id]: `${result.reopened} ${noun}${result.reopened === 1 ? '' : 's'} reopened` }));
      const updated = await api.listSuppressionRules();
      setRules(updated);
    } catch (e) {
      setExecuteMsg((m) => ({ ...m, [id]: e instanceof Error ? e.message : String(e) }));
    } finally {
      setReopeningAllId(null);
    }
  };

  const openEdit = (rule: SuppressionRule) => {
    setForm({
      name: rule.name,
      state: rule.state,
      recordType: rule.recordType,
      conditionsJson: rule.conditionsJson,
      conditionLogic: rule.conditionLogic,
      reason: rule.reason ?? '',
      validFrom: rule.validFrom ? rule.validFrom.slice(0, 16) : undefined,
      validTo: rule.validTo ? rule.validTo.slice(0, 16) : undefined,
    });
    setEditingId(rule.id);
    setSaveMsg('');
    setShowForm(true);
  };

  const cancelForm = () => { setShowForm(false); setEditingId(null); setSaveMsg(''); };

  const saveRule = async () => {
    if (!form.name.trim()) { setSaveMsg('Name is required'); return; }
    setSaving(true);
    setSaveMsg('');
    const payload: SuppressionRuleRequest = {
      name: form.name,
      state: form.state,
      recordType: form.recordType,
      conditionsJson: form.conditionsJson,
      conditionLogic: form.conditionLogic,
      reason: form.reason,
      validFrom: form.validFrom ? new Date(form.validFrom).toISOString() : undefined,
      validTo: form.validTo ? new Date(form.validTo).toISOString() : undefined,
    };
    try {
      if (editingId) {
        const updated = await api.updateSuppressionRule(editingId, payload);
        setRules((prev) => prev.map((r) => (r.id === editingId ? updated : r)));
        setSaveMsg('Saved');
      } else {
        const created = await api.createSuppressionRule(payload);
        setRules((prev) => [...prev, created]);
        setSaveMsg('Created');
        setShowForm(false);
        // The form closes on create, so the acknowledgement moves to the list.
        setListMessage(`Suppression rule "${created.name}" created in state ${created.state}.`);
      }
    } catch (e) {
      setSaveMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const deleteRule = (id: string) => {
    setDeleteError('');
    setListMessage('');
    setDeleteId(id);
  };

  // A rejected delete keeps the dialog open with the reason instead of replacing the whole list with an error.
  const confirmDeleteRule = async () => {
    if (!deleteId) return;
    setDeleting(true);
    setDeleteError('');
    try {
      await api.deleteSuppressionRule(deleteId);
      setRules((prev) => prev.filter((r) => r.id !== deleteId));
      setDeleteId(null);
      setListMessage('Suppression rule deleted.');
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  };

  if (loading || error) {
    return (
      <div className="config-section-body">
        <AsyncSection
          state={loading ? 'pending' : 'error'}
          loadingLabel="Loading suppression rules…"
          errorMessage={`Suppression rules could not be loaded. ${error}`}
          onRetry={loadRules}
        />
      </div>
    );
  }
  const ruleToDelete = rules.find((rule) => rule.id === deleteId);

  return (
    <div className="config-section-body">
      <div className="config-section-intro">
        <p>
          Suppression rules automatically suppress <strong>CVE</strong> or{' '}
          <strong>Finding</strong> records when all (or any) specified conditions match.
          Rules are evaluated in execution order.
        </p>
        <p>
          Suppressing a record hides it from active work without marking it fixed; it is not a resolution.
          Reopen All returns a rule's suppressed records to active work.
        </p>
      </div>

      {listMessage && <div className="notice" role="status" style={{ marginBottom: 12 }}>{listMessage}</div>}

      {/* Existing rules list — scrolls inside its own region so the page never widens. */}
      {rules.length > 0 && !showForm && (
        <div
          className="config-table-scroll"
          role="region"
          aria-label="Suppression rules"
          tabIndex={0}
          style={{ marginBottom: 20, maxWidth: '100%', overflowX: 'auto' }}
        >
          <table style={{ width: '100%', minWidth: 860, borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--dp-border)', color: 'var(--text-2)', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.71rem', letterSpacing: '0.04em' }}>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px 0' }}>Name</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Type</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>State</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Logic</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Valid from</th>
                <th style={{ textAlign: 'left', padding: '4px 8px 6px' }}>Valid to</th>
                <th style={{ textAlign: 'right', padding: '4px 8px 6px' }}>Suppressed</th>
                <th style={{ padding: '4px 0 6px' }} />
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <React.Fragment key={rule.id}>
                  <tr style={{ borderBottom: executeMsg[rule.id] ? 'none' : '1px solid var(--dp-border)' }}>
                    <td style={{ padding: '6px 8px 6px 0', fontWeight: 600 }}>{rule.name}</td>
                    <td style={{ padding: '6px 8px' }}>{rule.recordType}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ color: stateBadgeColor(rule.state), fontWeight: 600, fontSize: '0.78rem' }}>{rule.state}</span>
                    </td>
                    <td style={{ padding: '6px 8px', color: 'var(--text-2)' }}>{rule.conditionLogic}</td>
                    <td style={{ padding: '6px 8px', color: 'var(--text-2)' }}>{formatInstant(rule.validFrom)}</td>
                    <td style={{ padding: '6px 8px', color: 'var(--text-2)' }}>{formatInstant(rule.validTo)}</td>
                    <td style={{ padding: '6px 8px', textAlign: 'right', fontWeight: 600, color: rule.suppressedCount > 0 ? 'var(--dp-medium)' : 'var(--text-2)' }}>
                      {rule.suppressedCount}
                    </td>
                    <td style={{ padding: '6px 0', whiteSpace: 'nowrap', textAlign: 'right' }}>
                      {canEdit && (
                        <>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '2px 8px', marginRight: 6, opacity: rule.state !== 'APPROVED' ? 0.45 : 1 }}
                            onClick={() => executeRule(rule.id)}
                            disabled={executingId === rule.id || rule.state !== 'APPROVED'}
                            title={rule.state !== 'APPROVED' ? 'Only APPROVED rules can be executed' : 'Evaluate this rule against all open records and suppress matches'}
                          >
                            {executingId === rule.id ? 'Running…' : 'Execute Now'}
                          </button>
                          {rule.suppressedCount > 0 && (
                            <button
                              type="button"
                              className="btn btn-secondary"
                              style={{ fontSize: '0.75rem', padding: '2px 8px', marginRight: 6, color: 'var(--dp-warning)' }}
                              onClick={() => reopenAll(rule.id)}
                              disabled={reopeningAllId === rule.id}
                              title={`Reopen all ${rule.suppressedCount} suppressed record${rule.suppressedCount === 1 ? '' : 's'}`}
                            >
                              {reopeningAllId === rule.id ? 'Reopening…' : 'Reopen All'}
                            </button>
                          )}
                          <button type="button" className="btn-link" style={{ fontSize: '0.78rem', marginRight: 8 }} onClick={() => openEdit(rule)}>Edit</button>
                          <button type="button" className="btn-link" style={{ fontSize: '0.78rem', color: 'var(--dp-critical)' }} onClick={() => deleteRule(rule.id)}>Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                  {executeMsg[rule.id] && (
                    <tr style={{ borderBottom: '1px solid var(--dp-border)' }}>
                      <td colSpan={8} style={{ padding: '2px 8px 6px 0', fontSize: '0.78rem', color: executeMsg[rule.id].includes('suppressed') ? 'var(--dp-low)' : 'var(--dp-critical)' }}>
                        {executeMsg[rule.id]}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {rules.length === 0 && !showForm && (
        <div className="inline-note" style={{ marginBottom: 16 }}>No suppression rules defined yet.</div>
      )}

      {/* Form */}
      {showForm ? (
        <div style={{ background: 'var(--dp-surface-2)', border: '1px solid var(--dp-border)', borderRadius: 6, padding: 16, marginBottom: 16 }}>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', marginBottom: 12 }}>
            {editingId ? 'Edit Suppression Rule' : 'New Suppression Rule'}
          </div>

          {/* Details row */}
          <div className="form-grid ingestion-grid" style={{ marginBottom: 12 }}>
            <label>Name *
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Suppress low-severity CVEs"
              />
            </label>
            <label>Record Type
              <select value={form.recordType} onChange={(e) => setForm((f) => ({ ...f, recordType: e.target.value as SuppressionRuleRequest['recordType'] }))}>
                <option value="FINDING">Findings</option>
                <option value="CVE">CVEs</option>
              </select>
            </label>
            <label>State
              <select value={form.state} onChange={(e) => setForm((f) => ({ ...f, state: e.target.value as SuppressionRuleRequest['state'] }))}>
                <option value="DRAFT">Draft</option>
                <option value="IN_REVIEW">In Review</option>
                <option value="APPROVED">Approved</option>
                <option value="REJECTED">Rejected</option>
                <option value="EXPIRED">Expired</option>
              </select>
            </label>
            <label>Valid From
              <input type="datetime-local" value={form.validFrom ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, validFrom: e.target.value || undefined }))} />
            </label>
            <label>Valid To
              <input type="datetime-local" value={form.validTo ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, validTo: e.target.value || undefined }))} />
            </label>
          </div>

          {/* Condition builder */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span style={{ fontWeight: 600, fontSize: '0.82rem' }}>Conditions</span>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-2)' }}>Suppress when</span>
              <select
                value={form.conditionLogic}
                style={{ width: 80, margin: 0, fontSize: '0.8rem' }}
                onChange={(e) => setForm((f) => ({ ...f, conditionLogic: e.target.value as 'AND' | 'OR' }))}
              >
                <option value="AND">ALL (AND)</option>
                <option value="OR">ANY (OR)</option>
              </select>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-2)' }}>of these conditions match:</span>
            </div>

            {conditions.map((cond, i) => {
              const colType = getColumnDataType(cond.table, cond.column);
              const operators = getOperatorsForType(colType);
              const isBoolean = colType === 'boolean';
              const isNumeric = colType === 'numeric';
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, background: 'var(--panel-bg, var(--dp-bg))', border: '1px solid var(--dp-border)', borderRadius: 4, padding: '6px 10px' }}>
                  {i > 0 && (
                    <span style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--dp-accent)', minWidth: 28, textAlign: 'center' }}>
                      {form.conditionLogic}
                    </span>
                  )}
                  <select
                    value={cond.table}
                    style={{ width: 130, margin: 0, fontSize: '0.8rem' }}
                    onChange={(e) => updateCondition(i, 'table', e.target.value)}
                  >
                    {FINDINGS_SCORE_TABLES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                  <select
                    value={cond.column}
                    style={{ width: 160, margin: 0, fontSize: '0.8rem' }}
                    onChange={(e) => updateCondition(i, 'column', e.target.value)}
                  >
                    {(FINDINGS_SCORE_COLUMNS[cond.table] ?? []).map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                  <select
                    value={cond.operator}
                    style={{ width: 110, margin: 0, fontSize: '0.8rem' }}
                    onChange={(e) => updateCondition(i, 'operator', e.target.value)}
                  >
                    {operators.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
                  </select>
                  {isBoolean ? (
                    <select
                      value={cond.value}
                      style={{ width: 80, margin: 0, fontSize: '0.8rem' }}
                      onChange={(e) => updateCondition(i, 'value', e.target.value)}
                    >
                      <option value="true">true</option>
                      <option value="false">false</option>
                    </select>
                  ) : (
                    <input
                      type={isNumeric ? 'number' : 'text'}
                      placeholder="value"
                      value={cond.value}
                      onChange={(e) => updateCondition(i, 'value', e.target.value)}
                      style={{ width: 110, border: 'none', borderBottom: '1px solid var(--dp-border)', background: 'transparent', fontSize: '0.8rem', outline: 'none' }}
                    />
                  )}
                  {conditions.length > 1 && (
                    <button type="button" onClick={() => removeCondition(i)} style={{ border: 'none', background: 'none', color: 'var(--dp-critical)', cursor: 'pointer', fontSize: '1rem', lineHeight: 1, padding: '0 2px' }}>×</button>
                  )}
                </div>
              );
            })}

            <button type="button" className="btn-link" onClick={addCondition} style={{ fontSize: '0.8rem', marginTop: 4 }}>
              + New condition
            </button>
          </div>

          {/* Reason */}
          <div style={{ marginBottom: 12 }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '0.82rem', fontWeight: 600 }}>
              Reason
              <textarea
                value={form.reason ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
                placeholder="Explain why these records are being suppressed…"
                rows={3}
                style={{ resize: 'vertical', fontFamily: 'inherit', fontSize: '0.82rem', padding: '6px 8px', background: 'var(--panel-bg, var(--dp-bg))', border: '1px solid var(--dp-border)', borderRadius: 4, color: 'inherit' }}
              />
            </label>
          </div>

          <div className="button-row form-submit-row">
            <button type="button" className="btn btn-primary" onClick={saveRule} disabled={!canEdit || saving}>
              {saving ? 'Saving…' : editingId ? 'Update Rule' : 'Create Rule'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={cancelForm} disabled={saving}>Close</button>
            <span role="status" aria-live="polite">
              {saveMsg && (
                <span className="field-hint" style={{ marginLeft: 10, color: saveMsg === 'Saved' || saveMsg === 'Created' ? 'var(--dp-low)' : 'var(--dp-critical)' }}>
                  {saveMsg}
                </span>
              )}
            </span>
          </div>
        </div>
      ) : canEdit && (
        <div className="button-row form-submit-row">
          <button type="button" className="btn btn-secondary" onClick={openCreate}>
            + New Suppression Rule
          </button>
        </div>
      )}

      <ConfirmDialog
        isOpen={deleteId != null}
        title="Delete suppression rule?"
        message={(
          <>
            <p>This permanently deletes <strong>{ruleToDelete?.name ?? 'this rule'}</strong>.</p>
            {(ruleToDelete?.suppressedCount ?? 0) > 0 && (
              <p>
                It currently lists {ruleToDelete?.suppressedCount} suppressed record{ruleToDelete?.suppressedCount === 1 ? '' : 's'}.
                Reopen All is the action that returns them to active work.
              </p>
            )}
            {deleteError && <p className="notice error" role="alert">{deleteError}</p>}
          </>
        )}
        confirmLabel="Delete rule"
        busy={deleting}
        busyMessage="Deleting suppression rule…"
        onConfirm={() => void confirmDeleteRule()}
        onCancel={() => { setDeleteId(null); setDeleteError(''); }}
      />
    </div>
  );
}

// ── AutoFindingRulesSection ──────────────────────────────────────────────────

interface CveCondition {
  id: string;
  column: string;
  operator: string;
  value: string;
}

interface SelectedSoftware {
  id: string;
  vendor: string;
  name: string;
}

interface AutoFindingRule {
  id: string;
  name: string;
  enabled: boolean;
  investigate: boolean;
  createFindings: boolean;
  createServiceNowIncident: boolean;
  cveConditions: CveCondition[];
  softwareScope: 'ALL' | 'SPECIFIC';
  selectedSoftware: SelectedSoftware[];
  assetScope: 'ALL' | 'EXTERNAL_FACING' | 'SPECIFIC';
  assetTags: string;
  findingType: 'CVE_ASSET' | 'CVE_FIX';
  scheduleHours?: string;
  lastRunAt?: string;
  lastRunCreated?: number;
  lastRunReopened?: number;
  lastRunAlreadyOpen?: number;
  lastRunInvestigated?: number;
  lastRunIncidents?: number;
  lastRunSkipped?: number;
}

type AutoFindingRuleInput = Partial<Omit<AutoFindingRule, 'cveConditions' | 'selectedSoftware'>> & {
  cveConditions?: ReadonlyArray<CveCondition>;
  selectedSoftware?: ReadonlyArray<SelectedSoftware>;
};

function blankAutoFindingRule(): AutoFindingRule {
  return {
    id: crypto.randomUUID(),
    name: '',
    enabled: true,
    investigate: true,
    createFindings: true,
    createServiceNowIncident: false,
    cveConditions: [],
    softwareScope: 'ALL',
    selectedSoftware: [],
    assetScope: 'ALL',
    assetTags: '',
    findingType: 'CVE_ASSET',
    scheduleHours: '',
  };
}

interface CveColumnDef {
  value: string;
  label: string;
  type: 'text' | 'number' | 'boolean' | 'select';
  options?: string[];
}

const CVE_COLUMNS: CveColumnDef[] = [
  { value: 'description',          label: 'Description',           type: 'text' },
  { value: 'severity',             label: 'Severity',              type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
  { value: 'cvssScore',            label: 'CVSS Score',            type: 'number' },
  { value: 'epssScore',            label: 'EPSS Score',            type: 'number' },
  { value: 'exploitAvailable',     label: 'Exploit Available',     type: 'boolean' },
  { value: 'inKev',                label: 'In CISA KEV',           type: 'boolean' },
  { value: 'patchAvailable',       label: 'Patch Available',       type: 'boolean' },
  { value: 'attackVector',         label: 'Attack Vector',         type: 'select', options: ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'] },
  { value: 'attackComplexity',     label: 'Attack Complexity',     type: 'select', options: ['LOW', 'HIGH'] },
  { value: 'privilegesRequired',   label: 'Privileges Required',   type: 'select', options: ['NONE', 'LOW', 'HIGH'] },
  { value: 'userInteraction',      label: 'User Interaction',      type: 'select', options: ['NONE', 'REQUIRED'] },
  { value: 'scope',                label: 'Scope',                 type: 'select', options: ['UNCHANGED', 'CHANGED'] },
  { value: 'confidentialityImpact',label: 'Confidentiality Impact',type: 'select', options: ['NONE', 'LOW', 'HIGH'] },
  { value: 'integrityImpact',      label: 'Integrity Impact',      type: 'select', options: ['NONE', 'LOW', 'HIGH'] },
  { value: 'availabilityImpact',   label: 'Availability Impact',   type: 'select', options: ['NONE', 'LOW', 'HIGH'] },
];

function normalizeAutoFindingRule(rule: AutoFindingRuleInput): AutoFindingRule {
  const base = blankAutoFindingRule();
  const normalized: AutoFindingRule = {
    ...base,
    ...rule,
    id: rule.id ?? base.id,
    name: rule.name ?? base.name,
    enabled: rule.enabled ?? base.enabled,
    investigate: rule.investigate ?? true,
    createFindings: rule.createFindings ?? true,
    createServiceNowIncident: rule.createServiceNowIncident ?? false,
    cveConditions: (rule.cveConditions ?? base.cveConditions).map((condition) => ({ ...condition })),
    selectedSoftware: (rule.selectedSoftware ?? base.selectedSoftware).map((software) => ({ ...software })),
    softwareScope: rule.softwareScope ?? base.softwareScope,
    assetScope: rule.assetScope ?? base.assetScope,
    assetTags: rule.assetTags ?? base.assetTags,
    findingType: rule.findingType ?? base.findingType,
    scheduleHours: rule.scheduleHours ?? base.scheduleHours,
    lastRunAt: rule.lastRunAt,
    lastRunCreated: rule.lastRunCreated,
    lastRunReopened: rule.lastRunReopened,
    lastRunAlreadyOpen: rule.lastRunAlreadyOpen,
    lastRunInvestigated: rule.lastRunInvestigated,
    lastRunIncidents: rule.lastRunIncidents,
    lastRunSkipped: rule.lastRunSkipped,
  };
  if (normalized.createFindings) normalized.investigate = true;
  return normalized;
}

function operatorsFor(col: CveColumnDef): Array<{ value: string; label: string }> {
  switch (col.type) {
    case 'boolean': return [{ value: 'is_true', label: 'is true' }, { value: 'is_false', label: 'is false' }];
    case 'number':  return [{ value: '=', label: '=' }, { value: '>=', label: '>=' }, { value: '<=', label: '<=' }, { value: '>', label: '>' }, { value: '<', label: '<' }];
    case 'select':  return [{ value: '=', label: '=' }, { value: '!=', label: '≠' }];
    default:        return [{ value: 'contains', label: 'contains' }, { value: 'not_contains', label: 'does not contain' }, { value: '=', label: 'equals' }];
  }
}

function buildCriteriaFromCveDetail(detail: CveDetail): AssetCriterion[] {
  const seen = new Set<string>();
  const criteria: AssetCriterion[] = [];
  for (const matched of detail.matchedSoftware ?? []) {
    const software = matched.packageName?.trim() || matched.assetName?.trim() || '';
    if (!software) continue;
    const version = matched.version?.trim?.() || '';
    const vendor = matched.assetIdentifier?.trim?.() || matched.assetName?.trim() || '';
    const key = `${vendor.toLowerCase()}::${software.toLowerCase()}::${version.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    criteria.push({ id: matched.componentId, software, version, vendor });
  }
  return criteria;
}

function priorityFromSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const normalized = severity.trim().toUpperCase();
  if (normalized === 'CRITICAL') return 'CRITICAL';
  if (normalized === 'HIGH') return 'HIGH';
  if (normalized === 'LOW') return 'LOW';
  return 'MEDIUM';
}

function AutoFindingRulesSection({ canEdit }: { canEdit: boolean }) {
  const STORAGE_KEY = DEFAULT_AUTO_FINDING_RULES_STORAGE_KEY;

  const [rules, setRules] = React.useState<AutoFindingRule[]>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as AutoFindingRuleInput[];
        if (Array.isArray(parsed)) return parsed.map((rule) => normalizeAutoFindingRule(rule));
      }
    } catch { /* ignore */ }
    return DEFAULT_AUTO_FINDING_RULES.map((rule) => normalizeAutoFindingRule(rule as unknown as AutoFindingRuleInput));
  });

  React.useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(rules)); } catch { /* ignore */ }
  }, [rules]);
  const [showForm, setShowForm] = React.useState(false);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [form, setForm] = React.useState<AutoFindingRule>(blankAutoFindingRule());

  const openCreate = () => { setForm(blankAutoFindingRule()); setEditingId(null); setShowForm(true); };
  const openEdit   = (rule: AutoFindingRule) => { setForm(normalizeAutoFindingRule(rule)); setEditingId(rule.id); setShowForm(true); };

  const saveRule = () => {
    if (!form.name.trim()) return;
    const nextRule = normalizeAutoFindingRule(form);
    if (editingId) {
      setRules(prev => prev.map(r => r.id === editingId ? nextRule : r));
    } else {
      setRules(prev => [...prev, { ...nextRule, id: crypto.randomUUID() }]);
    }
    setShowForm(false); setEditingId(null);
  };

  const deleteRule    = (id: string) => setRules(prev => prev.filter(r => r.id !== id));
  const toggleEnabled = (id: string) => setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));

  const [executingId, setExecutingId] = React.useState<string | null>(null);
  const [executeError, setExecuteError] = React.useState<Record<string, string>>({});

  const executeRule = async (id: string) => {
    const rule = rules.find(r => r.id === id);
    if (!rule) return;

    setExecutingId(id);
    setExecuteError(prev => ({ ...prev, [id]: '' }));

    try {
      if (!rule.investigate && !rule.createFindings && !rule.createServiceNowIncident) {
        throw new Error('Enable investigation, findings creation, or ServiceNow incident creation before running the rule.');
      }
      if (!rule.investigate && rule.createFindings) {
        throw new Error('Create findings requires investigation to be enabled.');
      }

      // ── 1. Build API query params from CVE conditions ──────────────────
      const apiParams: Parameters<typeof cveWorkbenchApi.listOrgSpecificCves>[0] = {
        page: 0, size: 500, includeAll: true,
      };
      for (const cond of rule.cveConditions) {
        if (cond.column === 'severity' && cond.operator === '=') {
          apiParams.severity = cond.value;
        } else if (cond.column === 'inKev' && cond.operator === 'is_true') {
          apiParams.inKev = true;
        } else if (cond.column === 'exploitAvailable' && cond.operator === 'is_true') {
          apiParams.exploitOnly = true;
        }
      }
      if (rule.softwareScope === 'SPECIFIC' && rule.selectedSoftware.length > 0) {
        apiParams.softwareIdentityId = rule.selectedSoftware[0].id;
      }

      // ── 2. Fetch matching CVEs ─────────────────────────────────────────
      const page = await cveWorkbenchApi.listOrgSpecificCves(apiParams);
      let cves: OrgSpecificCveExposureRecord[] = page.items;

      // ── 3. Client-side filter for numeric/text conditions not in API ───
      for (const cond of rule.cveConditions) {
        if (cond.column === 'cvssScore') {
          const v = parseFloat(cond.value);
          if (!isNaN(v)) {
            cves = cves.filter(c => {
              const score = c.cvssScore ?? 0;
              if (cond.operator === '>=') return score >= v;
              if (cond.operator === '<=') return score <= v;
              if (cond.operator === '>')  return score > v;
              if (cond.operator === '<')  return score < v;
              return Math.abs(score - v) < 0.01;
            });
          }
        } else if (cond.column === 'epssScore') {
          const v = parseFloat(cond.value);
          if (!isNaN(v)) {
            // epssScore is stored as 0–1 decimal; user enters percentage (e.g. 9.3 = 9.3%)
            cves = cves.filter(c => {
              const scoreAsPct = (c.epssScore ?? 0) * 100;
              if (cond.operator === '>=') return scoreAsPct >= v;
              if (cond.operator === '<=') return scoreAsPct <= v;
              if (cond.operator === '>')  return scoreAsPct > v;
              if (cond.operator === '<')  return scoreAsPct < v;
              return Math.abs(scoreAsPct - v) < 0.01; // approximate equality for floats
            });
          }
        } else if (cond.column === 'inKev' && cond.operator === 'is_false') {
          cves = cves.filter(c => !c.inKev);
        } else if (cond.column === 'exploitAvailable' && cond.operator === 'is_false') {
          // no direct field on record; skip client filter
        } else if (cond.column === 'description' && cond.value.trim()) {
          const needle = cond.value.trim().toLowerCase();
          cves = cves.filter(c => {
            const hay = (c.descriptionSnippet ?? c.title ?? '').toLowerCase();
            if (cond.operator === 'not_contains') return !hay.includes(needle);
            if (cond.operator === '=') return hay === needle;
            return hay.includes(needle); // 'contains'
          });
        } else if (cond.column === 'severity' && cond.operator === '!=') {
          cves = cves.filter(c => (c.severity ?? '').toUpperCase() !== cond.value.toUpperCase());
        } else if (cond.column === 'patchAvailable' && cond.operator === 'is_true') {
          // no direct patchAvailable field on record — skip
        } else if (cond.column === 'patchAvailable' && cond.operator === 'is_false') {
          // no direct patchAvailable field on record — skip
        }
      }

      // ── 4. Create findings for each matched CVE ────────────────────────
      let totalCreated = 0;
      let totalReopened = 0;
      let totalAlreadyOpen = 0;
      let totalInvestigated = 0;
      let totalIncidents = 0;
      let totalSkipped = 0;
      const cveErrors: string[] = [];

      const buildServiceNowIncidentPayload = (
        cve: OrgSpecificCveExposureRecord,
        detail: CveDetail,
      ): CreateServiceNowIncidentRequest => {
        const solutionInfo = (() => {
          if (detail.signals.patchAvailable && detail.signals.patchVersions) {
            return `Upgrade to version ${detail.signals.patchVersions} or later to remediate ${cve.externalId}. Validate the patch on all impacted assets after deployment.`;
          }
          if (detail.signals.patchAvailable) {
            return `A vendor patch is available for ${cve.externalId}. Upgrade to the latest vendor-released version and validate the mitigation on impacted assets.`;
          }
          return `No vendor patch is currently available for ${cve.externalId}. Apply compensating controls (e.g. network isolation, privilege restrictions) and monitor vendor advisories for remediation guidance.`;
        })();

        return {
          findingTitle: detail.summary.title ?? cve.externalId,
          severity: detail.summary.severity ?? cve.severity ?? 'UNKNOWN',
          cvssScore: detail.summary.cvssScore ?? cve.cvssScore ?? undefined,
          epssScore: detail.summary.epssScore ?? cve.epssScore ?? undefined,
          inKev: detail.summary.inKev ?? cve.inKev ?? false,
          priority: priorityFromSeverity(cve.severity),
          notes: `Auto-created by rule: ${rule.name}`,
          solutionInfo,
          affectedAssets: detail.matchedSoftware.map((software) => ({
            componentId: software.componentId,
            assetName: software.assetName,
            assetIdentifier: software.assetIdentifier,
            assetType: software.assetType,
            packageName: software.packageName,
            packageVersion: software.version ?? undefined,
          })),
        };
      };

      for (const cve of cves) {
        try {
          const detail = await cveWorkbenchApi.getCveDetail(cve.externalId);
          const componentIds = detail.matchedSoftware.map(s => s.componentId).filter(Boolean);
          const hasInvestigationSummary =
            (detail.investigations?.some((investigation) => investigation.status === 'CLOSED') ?? false) ||
            (detail.assessments?.some((assessment) => assessment.status === 'COMPLETED') ?? false);
          let investigationDone = hasInvestigationSummary;
          const persistedRunbookState = loadPersistedInvestigationRunbookState(cve.externalId);

          if (rule.investigate) {
            const criteria = buildCriteriaFromCveDetail(detail);
            const runAgentResult = await cveWorkbenchApi.runAgent(cve.externalId, { criteria });
            await cveWorkbenchApi.submitCveInvestigation(cve.externalId, {
              status: 'CLOSED',
              priority: priorityFromSeverity(cve.severity),
              notes: `Auto investigation completed by rule: ${rule.name}`,
            });

            if (runAgentResult.resolved.length > 0) {
              const additionalSoftware = runAgentResult.resolved.map((entry) => ({
                name: entry.software,
                vendor: entry.vendor,
                version: entry.version,
                assetCount: entry.assets.length,
              }));
              await cveWorkbenchApi.generateFixRecords(cve.externalId, additionalSoftware).catch(() => undefined);
            }

            const nowIso = new Date().toISOString();
            const taskMeta = runAgentResult.taskMeta ?? {};
            const completedTaskIds = [...AUTO_INVESTIGATION_RUNBOOK_TASK_IDS];
            const taskStates: RunbookTaskStateRecord[] = completedTaskIds.map((taskId) => ({
              taskId,
              state: 'DONE',
              producedBy: 'AGENT',
              confidence: taskMeta[taskId]?.confidence === 'HIGH'
                || taskMeta[taskId]?.confidence === 'MEDIUM'
                || taskMeta[taskId]?.confidence === 'LOW'
                ? taskMeta[taskId].confidence
                : 'HIGH',
              completedAt: nowIso,
            }));
            const logEntries: RunbookLogEntryRecord[] = [
              {
                id: crypto.randomUUID(),
                type: 'AGENT',
                message: `Auto investigation completed by rule: ${rule.name}`,
                actor: 'Automation',
                producedBy: 'AGENT',
                at: nowIso,
              },
            ];

            await cveWorkbenchApi.saveRunbook(cve.externalId, {
              taskStates,
              logEntries,
              leadAnalyst: 'Automation',
              agentConfidence: Object.fromEntries(
                completedTaskIds.map((taskId) => [
                  taskId,
                  taskMeta[taskId]?.confidence === 'HIGH'
                    || taskMeta[taskId]?.confidence === 'MEDIUM'
                    || taskMeta[taskId]?.confidence === 'LOW'
                    ? taskMeta[taskId].confidence
                    : 'HIGH',
                ])
              ),
            });

            await cveWorkbenchApi.generateInvestigationSummary(cve.externalId, {
              summary: {
                cveId: cve.externalId,
                title: detail.summary.title ?? cve.externalId,
                description: detail.summary.description ?? undefined,
                severity: detail.summary.severity ?? cve.severity ?? 'UNKNOWN',
                cvssScore: detail.summary.cvssScore ?? cve.cvssScore ?? undefined,
                epssScore: detail.summary.epssScore ?? cve.epssScore ?? undefined,
                inKev: detail.summary.inKev ?? cve.inKev ?? undefined,
                exploitAvailable: detail.signals.exploitAvailable ?? undefined,
                patchAvailable: detail.signals.patchAvailable ?? undefined,
                patchVersions: detail.signals.patchVersions ?? undefined,
              },
              investigation: {
                leadAnalyst: 'Automation',
              },
              runbookResults: taskStates.map((task) => ({
                id: task.taskId,
                title: task.taskId,
                state: task.state,
              })),
              affectedAssets: runAgentResult.resolved.flatMap((entry) => (
                entry.assets.map((asset) => ({
                  id: asset.componentId,
                  hostname: asset.assetName || asset.assetIdentifier || asset.packageName || asset.componentId,
                  ipAddress: asset.assetIdentifier || undefined,
                  os: asset.assetType || undefined,
                  owner: asset.ecosystem || undefined,
                  environment: asset.ecosystem || undefined,
                  externalFacing: Boolean(asset.assetIdentifier),
                  critical: (cve.severity ?? detail.summary.severity ?? 'UNKNOWN').toUpperCase() === 'CRITICAL',
                  matchedSoftware: [{
                    software: entry.software,
                    version: entry.version,
                  }],
                }))
              )),
              falsePositiveRows: runAgentResult.fpResults.map((row) => ({
                software: row.software,
                version: row.version,
                falsePositive: row.falsePositive,
                assetsNotImpacted: row.notImpactedAssetCount,
                vendorAdvisory: row.vendorAdvisory,
                vendorGuidance: row.vendorGuidance,
              })),
              eolRows: runAgentResult.eolResults.map((row) => ({
                software: row.software,
                vendor: row.vendor,
                version: row.version,
                lifecycle: row.lifecycle,
                endOfSupport: row.endOfSupport,
                endOfLife: row.endOfLife,
                recommendedUpgrade: row.recommendedUpgrade,
              })),
              solutionRows: detail.fixes?.map((fix) => ({
                software: fix.softwareEntities[0]?.name ?? fix.summary,
                version: fix.softwareEntities[0]?.version ?? undefined,
                vendor: fix.softwareEntities[0]?.ecosystem ?? undefined,
                impactedAssets: fix.softwareEntities[0]?.assetCount ?? 0,
                solutionType: fix.fixType,
                solutionDetail: fix.summary,
                targetVersion: fix.softwareEntities[0]?.version ?? undefined,
              })) ?? [],
            });

            persistInvestigationRunbookState(cve.externalId, {
              ...(persistedRunbookState ?? {}),
              doneTaskIds: completedTaskIds.slice(),
              leadAnalyst: 'Automation',
              logEntries: [
                ...(persistedRunbookState?.logEntries ?? []),
                {
                  id: crypto.randomUUID(),
                  type: 'AGENT',
                  message: `Auto investigation completed by rule: ${rule.name}`,
                  actor: 'Automation',
                  at: nowIso,
                },
              ],
              taskProducedBy: Object.fromEntries(completedTaskIds.map((taskId) => [taskId, 'AGENT'])) as Record<string, 'AGENT'>,
              taskConfidence: Object.fromEntries(completedTaskIds.map((taskId) => [taskId, taskMeta[taskId]?.confidence ?? 'HIGH'])) as Record<string, AgentConfidenceLevel>,
              assetCriteria: criteria.map((criterion): AssetInventoryCriterion => ({
                id: criterion.id,
                software: criterion.software,
                version: criterion.version,
                vendor: criterion.vendor,
                matched: true,
              })),
              investigationAssetCount: runAgentResult.totalAssets,
              investigationSoftwareCount: runAgentResult.resolved.length,
              investigationSoftwareSummary: runAgentResult.resolved.map((entry) => ({
                software: entry.software,
                vendor: entry.vendor,
                version: entry.version,
                assetCount: entry.assets.length,
              })),
              falsePositiveResults: runAgentResult.fpResults.map((row): FalsePositiveResult => ({
                id: row.id,
                software: row.software,
                version: row.version,
                falsePositive: row.falsePositive,
                notImpactedAssetCount: row.notImpactedAssetCount,
                vendorAdvisory: row.vendorAdvisory,
                vendorGuidance: row.vendorGuidance,
                statusLabel: row.statusLabel,
                statusDetail: row.statusDetail,
                statusTone: row.statusTone as FalsePositiveResult['statusTone'],
              })),
              falsePositiveRan: true,
              eolCriteria: criteria.map((criterion) => ({
                id: criterion.id,
                software: criterion.software,
                version: criterion.version,
                vendor: criterion.vendor,
              })),
              eolResults: runAgentResult.eolResults.map((row): EolAnalysisResult => ({
                id: row.id,
                software: row.software,
                vendor: row.vendor,
                version: row.version,
                lifecycle: row.lifecycle,
                endOfSupport: row.endOfSupport,
                endOfLife: row.endOfLife,
                recommendedUpgrade: row.recommendedUpgrade,
              })),
              eolAssessed: true,
            });

            investigationDone = true;
            totalInvestigated += 1;
          }

          let result: { createdCount: number; reopenedCount: number; alreadyOpenCount?: number } | null = null;
          if (rule.createFindings) {
            if (!investigationDone) {
              totalSkipped += 1;
              continue;
            }
            if (componentIds.length === 0) {
              totalSkipped += 1;
              continue;
            }

            const componentApplicabilityDecisions: Record<string, 'APPLICABLE'> =
              Object.fromEntries(componentIds.map(id => [id, 'APPLICABLE']));
            const componentAnalystDispositions: Record<string, 'IMPACTED'> =
              Object.fromEntries(componentIds.map(id => [id, 'IMPACTED']));
            const findingCreationMode = rule.findingType === 'CVE_FIX' ? 'CVE_FIX' : 'ASSET_CVE';

            result = await cveWorkbenchApi.createManualFindings(cve.externalId, {
              justification: `Auto-created by rule: ${rule.name}`,
              findingCreationMode,
              componentIds,
              componentApplicabilityDecisions,
              componentAnalystDispositions,
              existingFindingBehavior: 'ADD_TO_EXISTING',
            }).catch(async () => {
              // CVE_FIX may fail with a constraint violation when the primary component
              // already has a non-grouped finding. Fall back to ASSET_CVE so the
              // existing findings are at least counted/reopened correctly.
              if (findingCreationMode === 'CVE_FIX') {
                return cveWorkbenchApi.createManualFindings(cve.externalId, {
                  justification: `Auto-created by rule: ${rule.name}`,
                  findingCreationMode: 'ASSET_CVE',
                  componentIds,
                  componentApplicabilityDecisions,
                  componentAnalystDispositions,
                  existingFindingBehavior: 'ADD_TO_EXISTING',
                });
              }
              throw new Error('Finding creation failed');
            });
            totalCreated      += result.createdCount;
            totalReopened     += result.reopenedCount;
            totalAlreadyOpen  += result.alreadyOpenCount ?? 0;
          }

          if (rule.createServiceNowIncident) {
            if (detail.matchedSoftware.length === 0) {
              totalSkipped += 1;
              continue;
            }
            if (rule.createFindings && !investigationDone) {
              totalSkipped += 1;
              continue;
            }
            if (!rule.createFindings || (result != null && ((result.createdCount ?? 0) > 0 || (result.reopenedCount ?? 0) > 0))) {
              const snowPayload = buildServiceNowIncidentPayload(cve, detail);
              try {
                const snowRaw = await cveWorkbenchApi.createServiceNowIncident(cve.externalId, snowPayload);
                const snowResults = Array.isArray(snowRaw) ? snowRaw : [snowRaw];
                totalIncidents += snowResults.filter((incident) => incident?.status === 'created').length || snowResults.length;
              } catch (snowErr) {
                cveErrors.push(`${cve.externalId} ServiceNow: ${snowErr instanceof Error ? snowErr.message : String(snowErr)}`);
              }
            }
          }
        } catch (err) {
          cveErrors.push(`${cve.externalId}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      const errorSummary = cveErrors.length > 0 ? ` Errors on ${cveErrors.length} CVE(s): ${cveErrors[0]}` : '';
      if (cveErrors.length > 0) {
        setExecuteError(prev => ({ ...prev, [id]: `${cveErrors.length} CVE(s) failed.${errorSummary}` }));
      }

      setRules(prev => prev.map(r => r.id === id
        ? {
            ...r,
            lastRunAt: new Date().toISOString(),
            lastRunCreated: totalCreated,
            lastRunReopened: totalReopened,
            lastRunAlreadyOpen: totalAlreadyOpen,
            lastRunInvestigated: totalInvestigated,
            lastRunIncidents: totalIncidents,
            lastRunSkipped: totalSkipped,
          }
        : r
      ));
    } catch (err) {
      setExecuteError(prev => ({ ...prev, [id]: err instanceof Error ? err.message : 'Execution failed' }));
    } finally {
      setExecutingId(null);
    }
  };

  const inputStyle: React.CSSProperties = { padding: '6px 10px', border: '1px solid var(--dp-border)', borderRadius: 6, fontSize: 13, color: 'var(--dp-text)', background: 'var(--dp-surface)', width: '100%', boxSizing: 'border-box' };
  const sectionLabelStyle: React.CSSProperties = { fontSize: 11, fontWeight: 700, color: 'var(--dp-text-2)', textTransform: 'uppercase', letterSpacing: '0.06em', margin: '16px 0 8px' };

  return (
    <div>
      {rules.length === 0 && !showForm && (
        <p style={{ color: 'var(--dp-text-2)', fontSize: 13, marginBottom: 16 }}>
          No auto investigation rules configured. Rules run automatically when new CVEs are ingested or inventory is updated.
        </p>
      )}

      {rules.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
          {rules.map(rule => {
            const isRunning = executingId === rule.id;
            const hasRun = rule.lastRunAt != null;
            return (
              <React.Fragment key={rule.id}>
              <div style={{ border: '1px solid var(--dp-border)', borderRadius: 8, background: 'var(--dp-surface)', padding: '14px 16px', display: 'flex', gap: 14, alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--dp-text)' }}>{rule.name}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10, background: rule.enabled ? 'color-mix(in srgb, var(--dp-low) 15%, transparent)' : 'var(--dp-surface-2)', color: rule.enabled ? 'var(--dp-low)' : 'var(--dp-text-2)', border: `1px solid ${rule.enabled ? 'color-mix(in srgb, var(--dp-low) 30%, transparent)' : 'var(--dp-border)'}` }}>
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: 'color-mix(in srgb, var(--dp-accent) 10%, transparent)', color: 'var(--dp-accent)', border: '1px solid color-mix(in srgb, var(--dp-accent) 25%, transparent)' }}>
                      {rule.investigate
                        ? (rule.createFindings
                          ? (rule.createServiceNowIncident ? 'Investigate + Findings + Incident' : 'Investigate + Findings')
                          : (rule.createServiceNowIncident ? 'Investigate + Incident' : 'Investigate only'))
                        : (rule.createServiceNowIncident ? 'Incident only' : 'Findings only')}
                    </span>
                    {/* Last run findings count */}
                    {hasRun && !isRunning && (() => {
                      const created = rule.lastRunCreated ?? 0;
                      const reopened = rule.lastRunReopened ?? 0;
                      const alreadyOpen = rule.lastRunAlreadyOpen ?? 0;
                      const investigated = rule.lastRunInvestigated ?? 0;
                      const incidents = rule.lastRunIncidents ?? 0;
                      const skipped = rule.lastRunSkipped ?? 0;
                      const parts: string[] = [];
                      if (investigated > 0) parts.push(`${investigated} investigated`);
                      if (created > 0) parts.push(`${created} created`);
                      if (reopened > 0) parts.push(`${reopened} reopened`);
                      if (alreadyOpen > 0) parts.push(`${alreadyOpen} already open`);
                      if (incidents > 0) parts.push(`${incidents} incidents`);
                      if (skipped > 0) parts.push(`${skipped} skipped`);
                      if (parts.length === 0) parts.push('0 created');
                      return (
                        <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 10, background: 'color-mix(in srgb, var(--dp-low) 12%, transparent)', color: 'var(--dp-low)', border: '1px solid color-mix(in srgb, var(--dp-low) 28%, transparent)' }}>
                          ✓ {parts.join(' · ')}
                        </span>
                      );
                    })()}
                    {isRunning && (
                      <span style={{ fontSize: 11, color: 'var(--dp-text-2)', fontStyle: 'italic' }}>Running…</span>
                    )}
                    {!isRunning && executeError[rule.id] && (
                      <span style={{ fontSize: 11, color: 'var(--dp-critical)' }}>⚠ {executeError[rule.id]}</span>
                    )}
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, fontSize: 12, color: 'var(--dp-text-2)' }}>
                    {rule.cveConditions.length > 0 && (
                      <span>CVE: {rule.cveConditions.map(c => `${CVE_COLUMNS.find(col => col.value === c.column)?.label ?? c.column} ${c.operator} ${c.value}`).join(' · ')}</span>
                    )}
                    <span>· Software: {rule.softwareScope === 'ALL' ? 'All' : rule.selectedSoftware.length > 0 ? rule.selectedSoftware.map(s => s.name).join(', ') : 'Specific'}</span>
                    <span>· Assets: {rule.assetScope === 'ALL' ? 'All' : rule.assetScope === 'EXTERNAL_FACING' ? 'External facing' : rule.assetTags || 'Specific'}</span>
                    {rule.scheduleHours && rule.scheduleHours.trim() && (
                      <span>· Every {rule.scheduleHours.trim()}h</span>
                    )}
                    {hasRun && rule.lastRunAt && (
                      <span>· Last run {new Date(rule.lastRunAt).toLocaleString()}</span>
                    )}
                  </div>
                </div>
                {canEdit && (
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0, alignItems: 'center' }}>
                    <button type="button" className="btn btn-primary" style={{ padding: '4px 12px', fontSize: 12 }}
                      disabled={isRunning}
                      onClick={() => void executeRule(rule.id)}>
                      {isRunning ? '…' : 'Execute Now'}
                    </button>
                    <button type="button" className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => toggleEnabled(rule.id)}>{rule.enabled ? 'Disable' : 'Enable'}</button>
                    <button type="button" className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => openEdit(rule)}>Edit</button>
                    <button type="button" className="btn btn-danger"    style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => deleteRule(rule.id)}>Delete</button>
                  </div>
                )}
              </div>
              {showForm && editingId === rule.id && (
                <AutoFindingRuleForm
                  form={form}
                  setForm={setForm}
                  isEdit={true}
                  inputStyle={inputStyle}
                  sectionLabelStyle={sectionLabelStyle}
                  onSave={saveRule}
                  onCancel={() => { setShowForm(false); setEditingId(null); }}
                />
              )}
              </React.Fragment>
            );
          })}
        </div>
      )}

      {showForm && !editingId && (
        <AutoFindingRuleForm
          form={form}
          setForm={setForm}
          isEdit={false}
          inputStyle={inputStyle}
          sectionLabelStyle={sectionLabelStyle}
          onSave={saveRule}
          onCancel={() => { setShowForm(false); setEditingId(null); }}
        />
      )}

      {canEdit && !showForm && (
        <div className="button-row form-submit-row">
          <button type="button" className="btn btn-secondary" onClick={openCreate}>+ New Auto Investigation Rule</button>
        </div>
      )}
    </div>
  );
}

// ── AutoFindingRuleForm ───────────────────────────────────────────────────────

function AutoFindingRuleForm({
  form, setForm, isEdit, inputStyle, sectionLabelStyle, onSave, onCancel,
}: {
  form: AutoFindingRule;
  setForm: React.Dispatch<React.SetStateAction<AutoFindingRule>>;
  isEdit: boolean;
  inputStyle: React.CSSProperties;
  sectionLabelStyle: React.CSSProperties;
  onSave: () => void;
  onCancel: () => void;
}) {
  // ── CVE column picker state ───────────────────────────────────────────────
  const [colPickerOpen, setColPickerOpen] = React.useState(false);
  const colPickerRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (colPickerRef.current && !colPickerRef.current.contains(e.target as Node)) {
        setColPickerOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const addCondition = (col: CveColumnDef) => {
    const ops = operatorsFor(col);
    const newCond: CveCondition = {
      id: crypto.randomUUID(),
      column: col.value,
      operator: ops[0].value,
      value: col.type === 'boolean' ? '' : col.type === 'select' ? (col.options?.[0] ?? '') : '',
    };
    setForm(p => ({ ...p, cveConditions: [...p.cveConditions, newCond] }));
    setColPickerOpen(false);
  };

  const updateCondition = (id: string, patch: Partial<CveCondition>) =>
    setForm(p => ({ ...p, cveConditions: p.cveConditions.map(c => c.id === id ? { ...c, ...patch } : c) }));

  const removeCondition = (id: string) =>
    setForm(p => ({ ...p, cveConditions: p.cveConditions.filter(c => c.id !== id) }));

  // ── Software picker state ─────────────────────────────────────────────────
  const [softwareList, setSoftwareList] = React.useState<Array<{ id: string; vendor: string; name: string }>>([]);
  const [softwareSearch, setSoftwareSearch] = React.useState('');
  const [softwareLoading, setSoftwareLoading] = React.useState(false);
  const canSaveRule = form.investigate || form.createFindings || form.createServiceNowIncident;

  React.useEffect(() => {
    if (form.softwareScope !== 'SPECIFIC') return;
    setSoftwareLoading(true);
    api.listSoftwareIdentities({ page: 0, size: 200 })
      .then(page => {
        setSoftwareList(page.content.map(s => ({
          id: s.id,
          vendor: s.vendor ?? 'Unknown',
          name: s.product ?? s.displayName,
        })));
      })
      .catch(() => {/* silently fall back to empty */})
      .finally(() => setSoftwareLoading(false));
  }, [form.softwareScope]);

  const toggleSoftware = (item: { id: string; vendor: string; name: string }) => {
    setForm(p => {
      const exists = p.selectedSoftware.some(s => s.id === item.id);
      return {
        ...p,
        selectedSoftware: exists
          ? p.selectedSoftware.filter(s => s.id !== item.id)
          : [...p.selectedSoftware, item],
      };
    });
  };

  const filteredSoftware = softwareList.filter(s =>
    softwareSearch === '' ||
    s.name.toLowerCase().includes(softwareSearch.toLowerCase()) ||
    s.vendor.toLowerCase().includes(softwareSearch.toLowerCase())
  );

  // Group by vendor
  const vendorGroups = filteredSoftware.reduce<Record<string, Array<{ id: string; vendor: string; name: string }>>>((acc, s) => {
    const v = s.vendor;
    if (!acc[v]) acc[v] = [];
    acc[v].push(s);
    return acc;
  }, {});

  const labelStyle: React.CSSProperties = { fontSize: 12, fontWeight: 600, color: 'var(--dp-text-2)', textTransform: 'uppercase', letterSpacing: '0.04em' };
  const fieldStyle: React.CSSProperties = { display: 'flex', flexDirection: 'column', gap: 4 };

  return (
    <div style={{ border: '1px solid var(--dp-border)', borderRadius: 8, background: 'var(--dp-surface)', padding: '16px 20px', marginBottom: 16 }}>
      <h4 style={{ margin: '0 0 16px', fontSize: 15, fontWeight: 700, color: 'var(--dp-text)' }}>
        {isEdit ? 'Edit Rule' : 'New Auto Investigation Rule'}
      </h4>

      {/* ── 2-column body ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 32px', alignItems: 'start' }}>

        {/* ── LEFT: Rule Name + CVE Criteria ── */}
        <div>
          <div style={fieldStyle}>
            <label style={labelStyle}>Rule Name</label>
            <input style={inputStyle} placeholder="e.g. Critical KEV findings for external assets"
              value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
          </div>

          <p style={sectionLabelStyle}>CVE Criteria</p>

          {form.cveConditions.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10 }}>
              {form.cveConditions.map(cond => {
                const colDef = CVE_COLUMNS.find(c => c.value === cond.column)!;
                const ops = operatorsFor(colDef);
                return (
                  <div key={cond.id} style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--dp-text)', padding: '5px 8px', border: '1px solid var(--dp-border)', borderRadius: 5, background: 'var(--dp-surface-2)', whiteSpace: 'nowrap' }}>
                      {colDef.label}
                    </span>
                    {colDef.type !== 'boolean' && (
                      <select style={{ ...inputStyle, width: 110 }} value={cond.operator}
                        onChange={e => updateCondition(cond.id, { operator: e.target.value })}>
                        {ops.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
                      </select>
                    )}
                    {colDef.type === 'boolean' ? (
                      <select style={{ ...inputStyle, width: 130 }} value={cond.operator}
                        onChange={e => updateCondition(cond.id, { operator: e.target.value })}>
                        {ops.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
                      </select>
                    ) : colDef.type === 'select' ? (
                      <select style={{ ...inputStyle, width: 140, flex: 'none' }} value={cond.value}
                        onChange={e => updateCondition(cond.id, { value: e.target.value })}>
                        {colDef.options!.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                      </select>
                    ) : (
                      <input style={{ ...inputStyle, width: 120, flex: 'none' }}
                        type={colDef.type === 'number' ? 'number' : 'text'}
                        value={cond.value}
                        onChange={e => updateCondition(cond.id, { value: e.target.value })}
                        placeholder={colDef.type === 'number' ? '0' : 'value'} />
                    )}
                    <button type="button" onClick={() => removeCondition(cond.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--dp-text-2)', fontSize: 16, lineHeight: 1, padding: '4px 4px' }}>
                      ×
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          <div style={{ position: 'relative', display: 'inline-block' }} ref={colPickerRef}>
            <button type="button" className="btn btn-secondary"
              style={{ fontSize: 12, padding: '5px 12px' }}
              onClick={() => setColPickerOpen(v => !v)}>
              + Add Condition ▾
            </button>
            {colPickerOpen && (
              <div style={{
                position: 'absolute', top: '100%', left: 0, zIndex: 200, marginTop: 4,
                background: 'var(--dp-surface)', border: '1px solid var(--dp-border)', borderRadius: 8,
                boxShadow: '0 4px 16px rgba(0,0,0,0.12)', minWidth: 220, maxHeight: 320, overflowY: 'auto',
              }}>
                {CVE_COLUMNS.map(col => {
                  const alreadyAdded = form.cveConditions.some(c => c.column === col.value);
                  return (
                    <button key={col.value} type="button"
                      disabled={alreadyAdded}
                      onClick={() => addCondition(col)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '9px 14px',
                        background: alreadyAdded ? 'var(--dp-surface-2)' : 'none', border: 'none', cursor: alreadyAdded ? 'default' : 'pointer',
                        fontSize: 13, color: alreadyAdded ? 'var(--dp-text-2)' : 'var(--dp-text)', textAlign: 'left',
                      }}
                      onMouseEnter={e => { if (!alreadyAdded) (e.currentTarget as HTMLButtonElement).style.background = 'color-mix(in srgb, var(--dp-accent) 10%, var(--dp-surface))'; }}
                      onMouseLeave={e => { if (!alreadyAdded) (e.currentTarget as HTMLButtonElement).style.background = 'none'; }}
                    >
                      {alreadyAdded && <span style={{ color: 'var(--dp-accent)', fontSize: 12 }}>✓</span>}
                      {col.label}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* ── RIGHT: Actions + Scope + Schedule ── */}
        <div>
          {/* Investigation & Findings */}
          <p style={sectionLabelStyle}>Investigation &amp; Findings</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', padding: '4px 0' }}>
              <input
                type="checkbox"
                checked={form.investigate}
                style={{ marginTop: 2, flexShrink: 0 }}
                onChange={() => setForm((p) => {
                  const nextInvestigate = !p.investigate;
                  if (!nextInvestigate && !p.createFindings) return p;
                  return { ...p, investigate: nextInvestigate, createFindings: nextInvestigate ? p.createFindings : false };
                })}
              />
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--dp-text)' }}>Run investigation</div>
                <div style={{ fontSize: 12, color: 'var(--dp-text-2)', marginTop: 1 }}>Run assessment, false positive, EOL, and fix analysis before any findings are created.</div>
              </div>
            </label>
            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', padding: '4px 0' }}>
              <input
                type="checkbox"
                checked={form.createFindings}
                style={{ marginTop: 2, flexShrink: 0 }}
                onChange={() => setForm((p) => {
                  const nextCreate = !p.createFindings;
                  if (!nextCreate && !p.investigate) return p;
                  return { ...p, createFindings: nextCreate, investigate: nextCreate ? true : p.investigate };
                })}
              />
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--dp-text)' }}>Create findings</div>
                <div style={{ fontSize: 12, color: 'var(--dp-text-2)', marginTop: 1 }}>Only create findings after the investigation finishes successfully.</div>
              </div>
            </label>
          </div>

          {/* Finding Creation */}
          {form.createFindings && (
            <>
              <p style={sectionLabelStyle}>Finding Creation</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {(['CVE_ASSET', 'CVE_FIX'] as const).map(type => (
                  <label key={type} style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', padding: '4px 0' }}>
                    <input type="radio" name="findingType" value={type} checked={form.findingType === type}
                      onChange={() => setForm(p => ({ ...p, findingType: type }))} style={{ marginTop: 2, flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--dp-text)' }}>{type === 'CVE_ASSET' ? 'CVE + Asset' : 'CVE + Fix'}</div>
                      <div style={{ fontSize: 12, color: 'var(--dp-text-2)', marginTop: 1 }}>
                        {type === 'CVE_ASSET' ? 'One finding per matched asset. Tracks remediation by asset owner.' : 'One finding per available fix. Groups all affected assets under each patch.'}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </>
          )}

          {/* Software Scope */}
          {form.createFindings && (
            <>
              <p style={sectionLabelStyle}>Software Scope</p>
              <div style={fieldStyle}>
                <select style={inputStyle} value={form.softwareScope}
                  onChange={e => setForm(p => ({ ...p, softwareScope: e.target.value as AutoFindingRule['softwareScope'], selectedSoftware: [] }))}>
                  <option value="ALL">All software</option>
                  <option value="SPECIFIC">Specific software</option>
                </select>
              </div>
              {form.softwareScope === 'SPECIFIC' && (
                <div style={{ marginTop: 8, border: '1px solid var(--dp-border)', borderRadius: 7, background: 'var(--dp-surface-2)', overflow: 'hidden' }}>
                  <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--dp-border)', background: 'var(--dp-surface)' }}>
                    <input style={{ ...inputStyle, margin: 0 }} placeholder="Search vendors or software…"
                      value={softwareSearch} onChange={e => setSoftwareSearch(e.target.value)} />
                  </div>
                  {form.selectedSoftware.length > 0 && (
                    <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--dp-border)', display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {form.selectedSoftware.map(s => (
                        <span key={s.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 12, fontSize: 11, fontWeight: 500, background: 'color-mix(in srgb, var(--dp-accent) 12%, var(--dp-surface))', color: 'var(--dp-accent)', border: '1px solid color-mix(in srgb, var(--dp-accent) 28%, transparent)' }}>
                          {s.name}
                          <button type="button" onClick={() => toggleSoftware(s)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--dp-accent)', fontSize: 13, lineHeight: 1, padding: 0 }}>×</button>
                        </span>
                      ))}
                    </div>
                  )}
                  <div style={{ maxHeight: 220, overflowY: 'auto' }}>
                    {softwareLoading ? (
                      <p style={{ padding: '10px 14px', color: 'var(--dp-text-2)', fontSize: 13 }}>Loading software…</p>
                    ) : Object.keys(vendorGroups).length === 0 ? (
                      <p style={{ padding: '10px 14px', color: 'var(--dp-text-2)', fontSize: 13 }}>No software found.</p>
                    ) : (
                      Object.entries(vendorGroups).sort(([a], [b]) => a.localeCompare(b)).map(([vendor, items]) => (
                        <div key={vendor}>
                          <div style={{ padding: '5px 10px 3px', fontSize: 10, fontWeight: 700, color: 'var(--dp-text-2)', textTransform: 'uppercase', letterSpacing: '0.05em', background: 'var(--dp-surface-2)', borderBottom: '1px solid var(--dp-border)' }}>
                            {vendor}
                          </div>
                          {items.map(item => {
                            const checked = form.selectedSoftware.some(s => s.id === item.id);
                            return (
                              <label key={item.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', cursor: 'pointer', background: checked ? 'color-mix(in srgb, var(--dp-accent) 6%, var(--dp-surface))' : 'var(--dp-surface)', borderBottom: '1px solid var(--dp-border)' }}
                                onMouseEnter={e => { if (!checked) (e.currentTarget as HTMLLabelElement).style.background = 'var(--dp-surface-2)'; }}
                                onMouseLeave={e => { if (!checked) (e.currentTarget as HTMLLabelElement).style.background = 'var(--dp-surface)'; }}
                              >
                                <input type="checkbox" checked={checked} onChange={() => toggleSoftware(item)} />
                                <span style={{ fontSize: 13, color: 'var(--dp-text)' }}>{item.name}</span>
                              </label>
                            );
                          })}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Asset Scope */}
              <p style={sectionLabelStyle}>Asset Scope</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={fieldStyle}>
                  <select style={inputStyle} value={form.assetScope}
                    onChange={e => setForm(p => ({ ...p, assetScope: e.target.value as AutoFindingRule['assetScope'] }))}>
                    <option value="ALL">All assets</option>
                    <option value="EXTERNAL_FACING">External facing assets only</option>
                    <option value="SPECIFIC">Specific asset tags</option>
                  </select>
                </div>
                {form.assetScope === 'SPECIFIC' && (
                  <div style={fieldStyle}>
                    <label style={labelStyle}>Asset Tags (comma-separated)</label>
                    <input style={inputStyle} placeholder="e.g. production, payment-service"
                      value={form.assetTags} onChange={e => setForm(p => ({ ...p, assetTags: e.target.value }))} />
                  </div>
                )}
              </div>
            </>
          )}

          {/* Schedule */}
          <p style={sectionLabelStyle}>Schedule</p>
          <div style={fieldStyle}>
            <label style={labelStyle}>Run every (hours)</label>
            <input
              style={{ ...inputStyle, maxWidth: 160 }}
              type="text"
              placeholder="e.g. 24"
              value={form.scheduleHours ?? ''}
              onChange={e => setForm(p => ({ ...p, scheduleHours: e.target.value }))}
            />
            <span style={{ fontSize: 11, color: 'var(--dp-text-2)', marginTop: 2 }}>Leave blank to run manually only</span>
          </div>
        </div>
      </div>

      {/* ── Full-width footer ── */}
      <div style={{ borderTop: '1px solid var(--dp-border)', marginTop: 16, paddingTop: 14 }}>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', padding: '4px 0' }}>
          <input
            type="checkbox"
            checked={form.createServiceNowIncident}
            style={{ marginTop: 2, flexShrink: 0 }}
            onChange={() => setForm(p => ({ ...p, createServiceNowIncident: !p.createServiceNowIncident }))}
          />
          <div>
            <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--dp-text)' }}>Create ServiceNow incident</div>
            <div style={{ fontSize: 12, color: 'var(--dp-text-2)', marginTop: 1 }}>Open a ServiceNow incident when the rule matches. If findings are also enabled, incidents are created after findings are created or reopened.</div>
          </div>
        </label>

        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <button type="button" className="btn btn-primary" disabled={!form.name.trim() || !canSaveRule} onClick={onSave}>
            {isEdit ? 'Save Changes' : 'Create Rule'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onCancel}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
