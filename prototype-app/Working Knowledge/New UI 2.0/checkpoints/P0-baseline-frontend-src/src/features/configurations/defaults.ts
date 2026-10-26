export const DEFAULT_FINDINGS_SCORE_CONFIG_JSON = JSON.stringify([
  {
    table: 'VULNERABILITY',
    column: 'cvssScore',
    values: [
      { operator: '>=', value: '9', weight: 0.2 },
      { operator: '<=', value: '8', weight: 0.1 },
    ],
  },
  {
    table: 'VULNERABILITY',
    column: 'exploitExists',
    values: [
      { operator: '=', value: 'true', weight: 0.2 },
    ],
  },
  {
    table: 'ASSET',
    column: 'businessCriticality',
    values: [
      { operator: '=', value: 'high', weight: 0.2 },
    ],
  },
  {
    table: 'ASSET',
    column: 'internetFacing',
    values: [
      { operator: '=', value: 'true', weight: 0.2 },
    ],
  },
  {
    table: 'VULNERABILITY',
    column: 'isInKev',
    values: [
      { operator: '=', value: 'true', weight: 0.2 },
    ],
  },
]);

export const DEFAULT_AUTO_FINDING_RULES_STORAGE_KEY = 'auto_finding_rules_v1';

export const DEFAULT_AUTO_FINDING_RULES = [
  {
    id: 'default-critical-applicable',
    name: 'Critical and Applicable',
    enabled: true,
    investigate: true,
    createFindings: true,
    createServiceNowIncident: false,
    cveConditions: [
      { id: 'default-critical-applicable-cond-1', column: 'cvssScore', operator: '>=', value: '9' },
    ],
    softwareScope: 'ALL',
    selectedSoftware: [],
    assetScope: 'ALL',
    assetTags: '',
    findingType: 'CVE_ASSET',
    scheduleHours: '24',
  },
] as const;
