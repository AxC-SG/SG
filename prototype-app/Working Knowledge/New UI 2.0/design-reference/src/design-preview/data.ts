// Static mock data for the design reference. Field names follow the real
// API/DTO shapes the pages render today so the visual mapping is 1:1.

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type FindingStatus = 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';

export type MockFinding = {
  id: string;
  cve: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  asset: string;
  assetType: 'HOST' | 'CONTAINER_IMAGE' | 'CLOUD_RESOURCE' | 'APPLICATION';
  owner: string | null;
  supportGroup: string | null;
  package: string;
  fixedIn: string | null;
  creationSource: 'AUTOMATIC' | 'MANUAL';
  risk: number;
  priority: number;
  epss: number;
  kev: boolean;
  ownerGroup: string | null;
  assignedTo: string | null;
  dueInDays: number | null;
  incidentId: string | null;
  incidentStatus: string | null;
  suppressionRule: string | null;
  firstObserved: string;
  lastObserved: string;
};

const CVES: Array<[string, string, string, string | null, Severity, number]> = [
  ['CVE-2026-31337', 'Remote code execution in log4j-core JNDI lookup', 'log4j-core', '2.25.3', 'critical', 9.8],
  ['CVE-2026-27104', 'OpenSSL heap overflow in X.509 name constraint check', 'openssl', '3.4.2', 'critical', 9.1],
  ['CVE-2026-20019', 'Spring Framework path traversal via static resources', 'spring-webmvc', '6.2.9', 'high', 8.6],
  ['CVE-2026-18822', 'Deserialization of untrusted data in jackson-databind', 'jackson-databind', '2.19.1', 'high', 8.1],
  ['CVE-2026-15503', 'Prototype pollution in lodash merge', 'lodash', '4.17.23', 'high', 7.5],
  ['CVE-2026-12977', 'nginx HTTP/3 QUIC memory disclosure', 'nginx', '1.29.1', 'medium', 6.5],
  ['CVE-2026-11410', 'Regular expression DoS in semver range parsing', 'semver', null, 'medium', 5.3],
  ['CVE-2026-09876', 'Information exposure in curl redirect handling', 'curl', '8.15.0', 'medium', 5.9],
  ['CVE-2026-08221', 'glibc iconv buffer overflow', 'glibc', '2.41-3', 'high', 7.8],
  ['CVE-2026-05530', 'PostgreSQL libpq SQL injection in quoting', 'postgresql-libs', '16.9', 'low', 3.7],
  ['CVE-2026-04012', 'Weak default cipher in urllib3', 'urllib3', '2.5.1', 'low', 3.1],
  ['CVE-2026-02987', 'Kubernetes kubelet privilege escalation', 'kubelet', '1.33.4', 'critical', 9.0],
];

const ASSETS: Array<[string, MockFinding['assetType']]> = [
  ['prod-api-gw-01', 'HOST'], ['payments-svc:3.14.2', 'CONTAINER_IMAGE'], ['i-0a93f2c7e1', 'CLOUD_RESOURCE'],
  ['checkout-web', 'APPLICATION'], ['etl-worker-07', 'HOST'], ['auth-svc:2.8.0', 'CONTAINER_IMAGE'],
  ['aks-node-pool-3', 'CLOUD_RESOURCE'], ['billing-core', 'APPLICATION'], ['vpn-edge-02', 'HOST'],
];

const OWNERS = ['Priya Raman', 'Marcus Lee', 'Ana Souza', null, 'Team Platform'];
const GROUPS = ['Payments Platform', 'Core Infra', 'Identity', null];
const STATUSES: FindingStatus[] = ['OPEN', 'OPEN', 'OPEN', 'OPEN', 'SUPPRESSED', 'AUTO_CLOSED', 'RESOLVED', 'SUPPRESSED'];

function seeded(n: number): number {
  const x = Math.sin(n * 9301 + 49297) * 233280;
  return x - Math.floor(x);
}

export const FINDINGS: MockFinding[] = Array.from({ length: 64 }, (_, i) => {
  const [cve, title, software, fixedIn, severity, cvss] = CVES[i % CVES.length];
  const [asset, assetType] = ASSETS[(i * 7) % ASSETS.length];
  const r = seeded(i + 1);
  const kev = severity === 'critical' ? r > 0.25 : r > 0.82;
  const epss = Math.round((severity === 'critical' ? 0.6 + r * 0.38 : r * 0.55) * 1000) / 1000;
  const status = STATUSES[i % STATUSES.length];
  const owner = OWNERS[(i * 3) % OWNERS.length];
  const hasIncident = i % 5 === 0;
  return {
    id: `F-${(10420 + i * 3).toString()}`,
    cve,
    title,
    severity,
    status,
    asset,
    assetType,
    owner,
    supportGroup: GROUPS[i % GROUPS.length],
    package: `${software}@${1 + (i % 4)}.${(i * 3) % 10}.${i % 7}`,
    fixedIn,
    creationSource: i % 6 === 0 ? 'MANUAL' : 'AUTOMATIC',
    risk: Math.round(cvss * 10) / 10,
    priority: Math.min(10, Math.round((cvss * 0.55 + epss * 3 + (kev ? 1.6 : 0)) * 10) / 10),
    epss,
    kev,
    ownerGroup: GROUPS[(i + 1) % GROUPS.length],
    assignedTo: owner,
    dueInDays: i % 9 === 0 ? null : Math.round(r * 40) - 8,
    incidentId: hasIncident ? `INC00${41200 + i}` : null,
    incidentStatus: hasIncident ? (i % 2 ? 'In Progress' : 'New') : null,
    suppressionRule: status === 'SUPPRESSED' ? 'Dev assets — 30d' : null,
    firstObserved: `2026-10-${String(1 + (i % 23)).padStart(2, '0')}`,
    lastObserved: '2026-10-24',
  };
});

export const STATUS_LABEL: Record<FindingStatus, string> = {
  OPEN: 'Open', RESOLVED: 'Resolved', SUPPRESSED: 'Deferred / Suppressed', AUTO_CLOSED: 'Closed',
};

// ── Exposure Dashboard (ExposureDashboardPage) ───────────────────────────
export const EXEC_KPIS = {
  criticalFindings: 84, openFindings: 1223, impacted: 412, impactedCritical: 37, impactedHigh: 118,
  kevImpacted: 29, needsAttention: 61, eol: 226, nearEol: 14,
};

export const GRID_EXPOSURE: Array<{ domain: string; critical: number; high: number; medium: number; low: number }> = [
  { domain: 'Hosts', critical: 31, high: 122, medium: 260, low: 98 },
  { domain: 'Container Images', critical: 27, high: 88, medium: 141, low: 52 },
  { domain: 'Cloud Resources', critical: 9, high: 41, medium: 77, low: 39 },
  { domain: 'Applications', critical: 17, high: 61, medium: 108, low: 52 },
  { domain: 'AI Assets', critical: 0, high: 4, medium: 11, low: 6 },
];

export const REMEDIATION = { unresolved: 51, inProgress: 18, resolved: 96, accepted: 7, securityScore: 72, avgRisk: 6.4 };

export const CRITICAL_CVES = CVES.filter((c) => c[4] === 'critical').map(([id, title], i) => ({
  id, title, exploitKnown: i !== 1, findingCount: [148, 96, 41][i] ?? 12,
}));

export const INSIGHTS: Array<{ level: 'critical' | 'warn' | 'info'; text: string; action: string }> = [
  { level: 'critical', text: '6 critical CVEs applicable to your environment have not been investigated.', action: 'Investigate now' },
  { level: 'critical', text: '3 new CISA KEV CVEs added this week with active exploits in the wild.', action: 'View new KEV' },
  { level: 'warn', text: 'Only 34% of confirmed impacted CVEs have an active remediation workflow.', action: 'Start remediation' },
  { level: 'info', text: '14 software components are nearing end-of-life — plan upgrades before security support ends.', action: 'View near-EOL' },
];

export const TOP_SOFTWARE = [
  { name: 'openssl', vendor: 'OpenSSL', cves: 11, assets: 412 },
  { name: 'glibc', vendor: 'GNU', cves: 7, assets: 380 },
  { name: 'log4j-core', vendor: 'Apache', cves: 6, assets: 148 },
  { name: 'jackson-databind', vendor: 'FasterXML', cves: 5, assets: 121 },
  { name: 'spring-webmvc', vendor: 'VMware', cves: 4, assets: 96 },
];

export const CRITICAL_ASSETS = [
  { name: 'prod-api-gw-01', type: 'Host', count: 42 },
  { name: 'payments-svc:3.14.2', type: 'Container Image', count: 37 },
  { name: 'billing-core', type: 'Application', count: 29 },
  { name: 'aks-node-pool-3', type: 'Cloud Resource', count: 22 },
  { name: 'vpn-edge-02', type: 'Host', count: 19 },
];

// ── Connectors (ConnectPage) ─────────────────────────────────────────────
export type ConnectorHealth = 'healthy' | 'failing' | 'idle' | 'disabled';
export const CONNECTOR_SECTIONS: Array<{ title: string; description: string; items: Array<{ id: string; name: string; vendor: string; mark: string; health: ConnectorHealth; status: string; entitlement?: boolean; mockOnly?: boolean }> }> = [
  { title: 'Inventory', description: 'CMDB, cloud and AI sources that populate assets and software.', items: [
    { id: 'servicenow-cmdb', name: 'ServiceNow CMDB', vendor: 'ServiceNow', mark: 'servicenow', health: 'failing', status: 'Last sync failed 2h ago' },
    { id: 'sccm-cmdb', name: 'SCCM / MECM', vendor: 'Microsoft', mark: 'microsoft', health: 'disabled', status: 'Unavailable for the pilot. Existing inventory is retained.' },
    { id: 'aws-discovery', name: 'AWS Discovery', vendor: 'Amazon Web Services', mark: 'aws', health: 'healthy', status: 'Last sync 14m ago' },
    { id: 'azure-discovery', name: 'Azure Discovery', vendor: 'Microsoft Azure', mark: 'azure', health: 'disabled', status: 'Unavailable for the pilot. Existing inventory is retained.' },
    { id: 'ai-security-aws', name: 'AWS Bedrock', vendor: 'Amazon Web Services', mark: 'aws', health: 'healthy', status: 'Last sync 3h ago', entitlement: true },
    { id: 'ai-security-azure', name: 'Azure AI Foundry', vendor: 'Microsoft Azure', mark: 'azure', health: 'idle', status: 'Not configured', entitlement: true },
    { id: 'ai-security-copilot', name: 'Copilot Studio', vendor: 'Microsoft', mark: 'microsoft', health: 'disabled', status: 'Disabled', entitlement: true },
  ] },
  { title: 'BOM Management', description: 'SBOM, AI-BOM, CBOM and vendor BOM ingestion.', items: [
    { id: 'sbom-endpoint', name: 'SBOM Endpoint', vendor: 'Generic', mark: 'generic', health: 'healthy', status: 'Last fetch 6h ago' },
    { id: 'bom-management', name: 'BOM Management', vendor: 'Upload or URL', mark: 'generic', health: 'healthy', status: '12 BOMs ingested' },
  ] },

];

export const RUN_HISTORY = [
  { id: 'run-8f21', source: 'AWS Discovery', trigger: 'Scheduled', status: 'RUNNING', progress: 62, started: '10:42', duration: '—', records: '1,204 / 1,940' },
  { id: 'run-8f1d', source: 'ServiceNow CMDB', trigger: 'Scheduled', status: 'SUCCEEDED', progress: 100, started: '08:00', duration: '3m 12s', records: '18,904' },
  { id: 'run-8f0a', source: 'Azure Discovery', trigger: 'Manual', status: 'FAILED', progress: 37, started: '09:15', duration: '48s', records: '311' },
  { id: 'run-8ef9', source: 'SBOM Endpoint', trigger: 'Scheduled', status: 'SUCCEEDED', progress: 100, started: '04:00', duration: '1m 02s', records: '2,113' },
  { id: 'run-8ee2', source: 'AWS Bedrock', trigger: 'Scheduled', status: 'QUEUED', progress: 0, started: '—', duration: '—', records: '—' },
];

// ── Tenants (PlatformConsolePage → TenantLifecyclePanel) ─────────────────
export const TENANTS = [
  { id: 't-acme', name: 'Acme Corporation', owner: 'secops@acme.example', slug: 'acme', status: 'ACTIVE', demo: 'NOT_REQUESTED', plan: 'Enterprise', refreshes: 24, expires: null, created: '2026-03-02 09:14', schema: '2/2', initials: 'AC', color: '#6366f1' },
  { id: 't-globex', name: 'Globex Industries', owner: 'it@globex.example', slug: 'globex', status: 'SUSPENDED', demo: 'NOT_REQUESTED', plan: 'Growth', refreshes: 12, expires: null, created: '2026-05-18 16:40', schema: '2/2', initials: 'GI', color: '#0ea5e9' },
  { id: 't-initech', name: 'Initech', owner: 'demo@initech.example', slug: 'initech-demo', status: 'ACTIVE', demo: 'READY', plan: 'Demo', refreshes: 4, expires: '2026-11-07', created: '2026-10-08 11:02', schema: '2/2', initials: 'IN', color: '#f59e0b' },
  { id: 't-umbrella', name: 'Umbrella Labs', owner: '-', slug: 'umbrella', status: 'PROVISIONING', demo: 'REQUESTED', plan: 'Enterprise', refreshes: 24, expires: null, created: '2026-10-24 10:51', schema: '0/2', initials: 'UL', color: '#10b981' },
  { id: 't-hooli', name: 'Hooli', owner: '-', slug: 'hooli', status: 'PROVISIONING_FAILED', demo: 'NOT_REQUESTED', plan: 'Growth', refreshes: 12, expires: null, created: '2026-10-23 17:20', schema: '1/2', initials: 'HO', color: '#ef4444' },
];
