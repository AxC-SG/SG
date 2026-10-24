// Navigation information architecture for the reference shell.
//
// Labels, order and destinations mirror the live app exactly (App.tsx:
// visiblePrimaryNavTabs, titleForTab, INVENTORY_PILL_ORDER, AI_INVENTORY_NAV_ITEMS,
// CONFIGURATIONS_PILL_ORDER, ADMIN_PILL_ORDER). Only the *grouping headings*
// and icons are new — they are presentational. Role/entitlement gating stays
// in App.tsx and is not modelled here; this is the full-permission view.

export type Pattern = 'dashboard' | 'list' | 'detail' | 'catalog' | 'settings' | 'console' | 'graph';

export type NavLeaf = {
  label: string;
  appPath: string;
  /** Hash route of the mock page that demonstrates this screen, when one exists. */
  mock?: string;
  pattern: Pattern;
};

export type NavItem = NavLeaf & { icon: string; children?: NavLeaf[] };
export type NavGroup = { title?: string; items: NavItem[]; placement?: 'bottom' };

export const PATTERN_REFERENCE: Record<Pattern, { label: string; mock: string }> = {
  dashboard: { label: 'Dashboard — KPI row, cards, clickable breakdowns', mock: '/exposure' },
  list: { label: 'List — widgets, toolbar, filterable table, action dialogs', mock: '/findings' },
  detail: { label: 'Record detail — header, actions, tabs, property rail', mock: '/findings/FND-10528' },
  catalog: { label: 'Catalog — card grid, connector config form, run history', mock: '/connect' },
  settings: { label: 'Settings — section rail, forms, rule builder, save bar', mock: '/configurations/sla' },
  console: { label: 'Console — secondary rail, inline create form, lifecycle table', mock: '/platform/tenants' },
  graph: { label: 'Graph — React Flow canvas with tokenised nodes', mock: '/components#graph' },
};

const INVENTORY_CHILDREN: NavLeaf[] = [
  { label: 'Overview', appPath: '/inventory/overview', mock: '/inventory/overview', pattern: 'dashboard' },
  { label: 'Hosts', appPath: '/inventory/hosts', pattern: 'list' },
  { label: 'Software Entities', appPath: '/inventory/software-identities', mock: '/inventory/overview', pattern: 'list' },
  { label: 'Container Images', appPath: '/inventory/container-images', pattern: 'list' },
  { label: 'Applications', appPath: '/inventory/sbom', pattern: 'list' },
  { label: 'BOM Components', appPath: '/inventory/bom-components', pattern: 'list' },
  { label: 'BOM Inventory', appPath: '/inventory/bom-inventory', pattern: 'list' },
];

const AI_INVENTORY_CHILDREN: NavLeaf[] = [
  { label: 'Overview', appPath: '/inventory/ai', mock: '/inventory/ai/support-agent', pattern: 'dashboard' },
  ...['Agents', 'Prompts', 'Tools', 'Components', 'Models', 'Guardrails', 'Identities'].map((label) => ({
    label,
    appPath: label === 'Agents' ? '/inventory/ai/agents' : `/inventory/ai/assets?nativeKind=…`,
    pattern: 'list' as const,
  })),
  { label: 'MCP Servers', appPath: '/inventory/ai/mcp?artifactRole=MCP_SERVER', pattern: 'list' },
  { label: 'Data stores', appPath: '/inventory/ai/knowledge-data?artifactRole=DATA_STORE', pattern: 'list' },
  { label: 'Others', appPath: '/inventory/ai/assets?view=others', pattern: 'list' },
];

const CONFIG_CHILDREN: NavLeaf[] = [
  { label: 'SLA & Remediation', appPath: '/configurations/sla', mock: '/configurations/sla', pattern: 'settings' },
  { label: 'S.AI Prioritization', appPath: '/configurations/triage', mock: '/configurations/triage', pattern: 'settings' },
  { label: 'Workflow Automation', appPath: '/configurations/automation', mock: '/configurations/automation', pattern: 'settings' },
  { label: 'Ownership', appPath: '/configurations/ownership', mock: '/configurations/ownership', pattern: 'settings' },
  { label: 'Findings Score', appPath: '/configurations/findings-score', mock: '/configurations/findings-score', pattern: 'settings' },
  { label: 'Suppression Rules', appPath: '/configurations/suppress', mock: '/configurations/suppress', pattern: 'settings' },
  { label: 'Auto Investigation & Findings', appPath: '/configurations/auto-findings', mock: '/configurations/auto-findings', pattern: 'settings' },
];

const ADMIN_CHILDREN: NavLeaf[] = [
  { label: 'Users', appPath: '/admin/users', pattern: 'list' },
  { label: 'Invites', appPath: '/admin/invites', pattern: 'list' },
  { label: 'Roles & Permissions', appPath: '/admin/roles', pattern: 'settings' },
  { label: 'Service Accounts', appPath: '/admin/service-accounts', pattern: 'list' },
  { label: 'Audit', appPath: '/admin/audit', pattern: 'list' },
];

export const TENANT_NAV: NavGroup[] = [
  { items: [
    { label: 'Exposure', appPath: '/exposure', mock: '/exposure', pattern: 'dashboard', icon: 'gauge' },
  ] },
  { title: 'Remediation', items: [
    { label: 'Findings', appPath: '/findings', mock: '/findings', pattern: 'list', icon: 'shield', children: [
      { label: 'Vulnerability Findings', appPath: '/findings', mock: '/findings', pattern: 'list' },
      { label: 'AI Findings', appPath: '/findings/ai', mock: '/findings/ai', pattern: 'list' },
    ] },
    { label: 'Vulnerability Repository', appPath: '/vuln-repo', mock: '/vuln-repo/org-cves/CVE-2026-31337', pattern: 'dashboard', icon: 'book' },
    { label: 'Campaigns', appPath: '/vuln-repo/campaigns', pattern: 'list', icon: 'flag' },
  ] },
  { title: 'Assets', items: [
    { label: 'Inventory', appPath: '/inventory/overview', mock: '/inventory/overview', pattern: 'dashboard', icon: 'boxes', children: INVENTORY_CHILDREN },
    { label: 'AI Policies', appPath: '/policies', pattern: 'list', icon: 'scale' },
    { label: 'AI Inventory', appPath: '/inventory/ai', mock: '/inventory/ai/support-agent', pattern: 'dashboard', icon: 'bot', children: AI_INVENTORY_CHILDREN },
  ] },
  { placement: 'bottom', items: [
    { label: 'Connectors', appPath: '/connect/sources', mock: '/connect', pattern: 'catalog', icon: 'plug' },
    { label: 'Configurations', appPath: '/configurations/sla', mock: '/configurations/sla', pattern: 'settings', icon: 'settings', children: CONFIG_CHILDREN },
    { label: 'Administration', appPath: '/admin/users', pattern: 'list', icon: 'users', children: ADMIN_CHILDREN },
  ] },
];

// Platform-scope owner (App.tsx: ['vuln-repo', 'connect', 'platform', 'end-of-life', 'platform-policies'] + Operations).
export const PLATFORM_NAV: NavGroup[] = [
  { items: [
    { label: 'Vulnerability Repository', appPath: '/vuln-repo', mock: '/vuln-repo/org-cves/CVE-2026-31337', pattern: 'dashboard', icon: 'book' },
    { label: 'Connectors', appPath: '/connect/sources', mock: '/connect', pattern: 'catalog', icon: 'plug' },
    { label: 'Tenant Management', appPath: '/platform/tenants', mock: '/platform/tenants', pattern: 'console', icon: 'building' },
    { label: 'End-of-Life', appPath: '/platform/eol', pattern: 'list', icon: 'clock' },
    { label: 'Policy Distribution', appPath: '/platform/ai-policies', mock: '/platform/ai-policies', pattern: 'console', icon: 'shieldCheck' },
  ] },
  { title: 'Operations', items: [
    { label: 'Operations', appPath: '/platform/operations', pattern: 'dashboard', icon: 'activity' },
  ] },
];

export function flattenNav(groups: NavGroup[]): NavLeaf[] {
  return groups.flatMap((group) => group.items.flatMap((item) => [item, ...(item.children ?? [])]));
}
