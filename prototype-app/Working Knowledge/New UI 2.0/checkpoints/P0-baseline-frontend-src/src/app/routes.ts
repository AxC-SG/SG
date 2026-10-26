import type { InventoryViewKey } from '../features/inventory/types';

export type RouteSearchValue = string | number | boolean | null | undefined | Array<string | number | boolean>;

export type AppTab =
  | 'exposure'
  | 'dashboard'
  | 'findings'
  | 'fix-intelligence'
  | 'policies'
  | 'platform-policies'
  | 'operations'
  | 'vuln-repo'
  | 'campaigns'
  | 'inventory'
  | 'ai'
  | 'end-of-life'
  | 'connect'
  | 'admin'
  | 'platform'
  | 'configurations';

export type OperationsRouteView = 'quality' | 'pipeline' | 'platform-health';
export type VulnerabilityIntelRouteView = 'dashboard' | 'vulnerabilities' | 'campaigns' | 'end-of-life' | 'org-cves';
export type ConnectRouteView = 'sources' | 'run-history';
export type AdminRouteView = 'users' | 'invites' | 'roles' | 'service-accounts' | 'audit';
export type PlatformRouteView = 'tenants' | 'users' | 'platform-audit' | 'demo-requests' | 'operations' | 'vuln-intel' | 'eol' | 'ai-policies';
export type ConfigurationsRouteView =
  | 'sla'
  | 'triage'
  | 'automation'
  | 'ownership'
  | 'findings-score'
  | 'suppress'
  | 'auto-findings';
export type FixIntelligenceRouteView = 'all' | 'patches' | 'workarounds' | 'compensating-controls';

export const INVENTORY_DEFAULT_VIEW: InventoryViewKey = 'overview';
export const OPERATIONS_DEFAULT_VIEW: OperationsRouteView = 'pipeline';
export const CONNECT_DEFAULT_VIEW: ConnectRouteView = 'sources';
export const ADMIN_DEFAULT_VIEW: AdminRouteView = 'users';
export const PLATFORM_DEFAULT_VIEW: PlatformRouteView = 'tenants';
export const CONFIGURATIONS_DEFAULT_VIEW: ConfigurationsRouteView = 'sla';
export const FIX_INTELLIGENCE_DEFAULT_VIEW: FixIntelligenceRouteView = 'all';

const OPERATIONS_VIEW_ALIASES: Record<string, OperationsRouteView> = {
  dashboard: 'pipeline',
  overview: 'pipeline',
  pipeline: 'pipeline',
  quality: 'quality',
  'ingestion-efficiency': 'pipeline',
  ingestion: 'pipeline',
  'normalization-quality': 'pipeline',
  normalization: 'pipeline',
  'correlation-effectiveness': 'pipeline',
  correlation: 'pipeline',
  'noise-lifecycle': 'pipeline',
  noise: 'pipeline',
  lifecycle: 'pipeline',
  freshness: 'pipeline',
  'freshness-drift': 'pipeline',
  'platform-health': 'platform-health',
  'api-read-path': 'platform-health',
  readPath: 'platform-health',
  'metric-catalog': 'platform-health',
  catalog: 'platform-health',
  slo: 'platform-health'
};

const INVENTORY_VIEWS = new Set<InventoryViewKey>([
  'overview',
  'software-identities',
  'hosts',
  'container-images',
  'sbom',
  'bom-components',
  'bom-inventory',
  'ai'
]);

const CONNECT_VIEWS = new Set<ConnectRouteView>([
  'sources',
  'run-history'
]);

const ADMIN_VIEWS = new Set<AdminRouteView>([
  'users',
  'invites',
  'roles',
  'service-accounts',
  'audit'
]);

const PLATFORM_VIEWS = new Set<PlatformRouteView>(['tenants', 'users', 'platform-audit', 'demo-requests', 'operations', 'vuln-intel', 'eol', 'ai-policies']);

const CONFIGURATIONS_VIEWS = new Set<ConfigurationsRouteView>([
  'sla',
  'triage',
  'automation',
  'ownership',
  'findings-score',
  'suppress',
  'auto-findings'
]);

const FIX_INTELLIGENCE_VIEWS = new Set<FixIntelligenceRouteView>([
  'all',
  'patches',
  'workarounds',
  'compensating-controls'
]);

export function normalizeOperationsRouteView(value: string | null | undefined): OperationsRouteView {
  if (!value) {
    return OPERATIONS_DEFAULT_VIEW;
  }
  if (value === 'quality' || value === 'pipeline' || value === 'platform-health') {
    return value;
  }
  return OPERATIONS_VIEW_ALIASES[value] ?? OPERATIONS_DEFAULT_VIEW;
}

export function normalizeInventoryRouteView(value: string | null | undefined): InventoryViewKey {
  if (!value) {
    return INVENTORY_DEFAULT_VIEW;
  }
  if (value === 'overview' || value === 'summary' || value === 'dashboard') {
    return 'overview';
  }
  if (value === 'imported-assets') {
    return 'software-identities';
  }
  if (value === 'applications' || value === 'application-inventory' || value === 'repositories' || value === 'repository-inventory') {
    return 'sbom';
  }
  if (value === 'images' || value === 'image-inventory' || value === 'container-image-inventory') {
    return 'container-images';
  }
  if (value === 'host-review-queue' || value === 'host-details') {
    return 'hosts';
  }
  return INVENTORY_VIEWS.has(value as InventoryViewKey) ? value as InventoryViewKey : INVENTORY_DEFAULT_VIEW;
}

export function normalizeConnectRouteView(value: string | null | undefined): ConnectRouteView {
  if (!value) {
    return CONNECT_DEFAULT_VIEW;
  }
  if (value === 'github-pipelines' || value === 'feeds' || value === 'central-repository' || value === 'connectors') {
    return 'sources';
  }
  if (value === 'integration-queue' || value === 'inventory-run-queue' || value === 'vuln-intel-queue' || value === 'integration-run-queue') {
    return 'run-history';
  }
  return CONNECT_VIEWS.has(value as ConnectRouteView) ? value as ConnectRouteView : CONNECT_DEFAULT_VIEW;
}

export function normalizeAdminRouteView(value: string | null | undefined): AdminRouteView {
  if (!value) {
    return ADMIN_DEFAULT_VIEW;
  }
  return ADMIN_VIEWS.has(value as AdminRouteView) ? value as AdminRouteView : ADMIN_DEFAULT_VIEW;
}

export function normalizePlatformRouteView(value: string | null | undefined): PlatformRouteView {
  if (!value) {
    return PLATFORM_DEFAULT_VIEW;
  }
  return PLATFORM_VIEWS.has(value as PlatformRouteView) ? value as PlatformRouteView : PLATFORM_DEFAULT_VIEW;
}

export function pathForAdminView(view: AdminRouteView): string {
  return `/admin/${normalizeAdminRouteView(view)}`;
}

export function normalizeConfigurationsRouteView(value: string | null | undefined): ConfigurationsRouteView {
  if (!value) {
    return CONFIGURATIONS_DEFAULT_VIEW;
  }
  return CONFIGURATIONS_VIEWS.has(value as ConfigurationsRouteView) ? value as ConfigurationsRouteView : CONFIGURATIONS_DEFAULT_VIEW;
}

export function pathForConfigurationsView(view: ConfigurationsRouteView): string {
  return `/configurations/${normalizeConfigurationsRouteView(view)}`;
}

export function normalizeFixIntelligenceRouteView(value: string | null | undefined): FixIntelligenceRouteView {
  if (!value) {
    return FIX_INTELLIGENCE_DEFAULT_VIEW;
  }
  return FIX_INTELLIGENCE_VIEWS.has(value as FixIntelligenceRouteView) ? value as FixIntelligenceRouteView : FIX_INTELLIGENCE_DEFAULT_VIEW;
}

export function pathForFixIntelligenceView(view: FixIntelligenceRouteView): string {
  return `/fix-intelligence/${normalizeFixIntelligenceRouteView(view)}`;
}

export function pathForPlatformView(view: PlatformRouteView): string {
  return `/platform/${normalizePlatformRouteView(view)}`;
}

export function pathForTab(tab: AppTab): string {
  switch (tab) {
    case 'exposure':
      return '/exposure';
    case 'dashboard':
      return '/';
    case 'findings':
      return '/findings';
    case 'fix-intelligence':
      return '/fix-intelligence';
    case 'policies':
      return '/policies';
    case 'platform-policies':
      return pathForPlatformView('ai-policies');
    case 'operations':
      return `/operations/${OPERATIONS_DEFAULT_VIEW}`;
    case 'vuln-repo':
      return '/vuln-repo';
    case 'campaigns':
      return '/vuln-repo/campaigns';
    case 'inventory':
      return pathForInventoryView(INVENTORY_DEFAULT_VIEW);
    case 'ai':
      return pathForAiInventoryOverview();
    case 'end-of-life':
      return pathForPlatformView('eol');
    case 'connect':
      return `/connect/${CONNECT_DEFAULT_VIEW}`;
    case 'admin':
      return pathForAdminView(ADMIN_DEFAULT_VIEW);
    case 'platform':
      return pathForPlatformView(PLATFORM_DEFAULT_VIEW);
    case 'configurations':
      return pathForConfigurationsView(CONFIGURATIONS_DEFAULT_VIEW);
  }
}

export function pathForInventoryView(view: InventoryViewKey): string {
  if (view === 'overview') {
    return '/inventory';
  }
  return view === 'software-identities' ? '/inventory/software-identities' : `/inventory/${view}`;
}

export function pathForAiKnowledgeData(): string {
  return '/inventory/ai/knowledge-data';
}

export function pathForAiInventoryOverview(): string {
  return '/inventory/ai/overview';
}

export function pathForAiMcpInventory(): string {
  return '/inventory/ai/mcp';
}

export function pathForSoftwareIdentityDetail(softwareIdentityId: string): string {
  return `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`;
}

export function pathForPolicyDetail(policyId: string): string {
  return `/policies/${encodeURIComponent(policyId)}`;
}

export function pathForPlatformPolicyDetail(policyId: string): string {
  return `/platform/ai-policies/${encodeURIComponent(policyId)}`;
}

export function pathForAiBomDeclaredResources(): string {
  return '/inventory/ai/declared-resources';
}

export function pathForAiBomDeclaredResourceDetail(resourceId: string): string {
  return `/inventory/ai/declared-resources/${encodeURIComponent(resourceId)}`;
}

export function pathForAiFindings(tab?: 'violations' | 'vulnerabilities'): string {
  return tab === 'vulnerabilities' ? '/findings/ai/vulnerabilities' : '/findings/ai';
}

export function pathForAiFindingDetail(findingId: string, returnTo?: string): string {
  const encodedFindingId = encodeURIComponent(findingId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/findings/ai/${encodedFindingId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/findings/ai/${encodedFindingId}?${searchParams.toString()}`;
}

export function appendSearchToPath(
  path: string,
  values?: Record<string, RouteSearchValue>
): string {
  if (!values) {
    return path;
  }

  const searchParams = new URLSearchParams();
  const appendValue = (key: string, value: string | number | boolean | null | undefined): void => {
    if (value == null) {
      return;
    }
    const normalized = String(value).trim();
    if (!normalized) {
      return;
    }
    searchParams.append(key, normalized);
  };

  Object.entries(values).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((item) => appendValue(key, item));
      return;
    }
    appendValue(key, value);
  });

  return searchParams.size > 0 ? `${path}?${searchParams.toString()}` : path;
}

export function pathForInventoryViewWithSearch(
  view: InventoryViewKey,
  values?: Record<string, RouteSearchValue>
): string {
  return appendSearchToPath(pathForInventoryView(view), values);
}

export function pathForInventoryHostAsset(assetId: string, returnTo?: string): string {
  const encodedAssetId = encodeURIComponent(assetId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/inventory/hosts/${encodedAssetId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/inventory/hosts/${encodedAssetId}?${searchParams.toString()}`;
}

export function pathForInventoryAiAgents(values?: Record<string, RouteSearchValue>): string {
  return appendSearchToPath('/inventory/ai/agents', values);
}

export function pathForInventoryAiAssets(values?: Record<string, RouteSearchValue>): string {
  return appendSearchToPath('/inventory/ai/assets', values);
}

export function pathForInventoryAiAsset(assetId: string, returnTo?: string): string {
  const encodedAssetId = encodeURIComponent(assetId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/inventory/ai/${encodedAssetId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/inventory/ai/${encodedAssetId}?${searchParams.toString()}`;
}

export function pathForOperationsView(view: OperationsRouteView): string {
  return `/operations/${normalizeOperationsRouteView(view)}`;
}

export function pathForVulnRepoView(view: VulnerabilityIntelRouteView, cveId?: string | null): string {
  if (view === 'dashboard') {
    return '/vuln-repo';
  }
  if (view === 'vulnerabilities') {
    return '/vuln-repo/vulnerabilities';
  }
  if (view === 'campaigns') {
    return '/vuln-repo/campaigns';
  }
  if (view === 'end-of-life') {
    return pathForPlatformView('eol');
  }
  return cveId ? `/vuln-repo/org-cves/${encodeURIComponent(cveId)}` : '/vuln-repo/org-cves';
}

export function pathForPlatformVulnIntelDetail(externalId: string): string {
  return `/vuln-repo/intel/${encodeURIComponent(externalId)}`;
}

export function pathForVulnRepoCveAssets(cveId: string): string {
  return `/vuln-repo/org-cves/${encodeURIComponent(cveId)}/assets`;
}

export function pathForVulnRepoCveSoftware(cveId: string): string {
  return `/vuln-repo/org-cves/${encodeURIComponent(cveId)}/software`;
}

export function pathForVulnRepoSoftwareAssets(softwareIdentityId: string, software?: string): string {
  const searchParams = new URLSearchParams();
  searchParams.set('softwareIdentityId', softwareIdentityId);
  if (software && software.trim().length > 0) {
    searchParams.set('software', software.trim());
  }
  return `/vuln-repo/software-assets?${searchParams.toString()}`;
}

export function pathForVulnRepoHostAsset(assetId: string, returnTo?: string): string {
  const encodedAssetId = encodeURIComponent(assetId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/vuln-repo/host-assets/${encodedAssetId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/vuln-repo/host-assets/${encodedAssetId}?${searchParams.toString()}`;
}

export function pathForConnectView(view: ConnectRouteView): string {
  return `/connect/${normalizeConnectRouteView(view)}`;
}

export type FindingsFilterParams = {
  vulnerabilityId?: string;
  severity?: string[];
  status?: string[];
  packageName?: string;
  assetName?: string;
  assetType?: string[];
};

export function pathForFindingsWithFilters(params?: FindingsFilterParams): string {
  if (!params) return '/findings';
  const values: Record<string, RouteSearchValue> = {};
  if (params.vulnerabilityId) values.vulnerabilityId = params.vulnerabilityId;
  if (params.severity?.length) values.severity = params.severity;
  if (params.status?.length) values.status = params.status;
  if (params.packageName) values.packageName = params.packageName;
  if (params.assetName) values.assetName = params.assetName;
  if (params.assetType?.length) values.assetType = params.assetType;
  return appendSearchToPath('/findings', values);
}

export function pathForFindingDetail(displayId: string, returnTo?: string): string {
  const encodedId = encodeURIComponent(displayId);
  if (!returnTo || returnTo.trim().length === 0) {
    return `/findings/${encodedId}`;
  }
  const searchParams = new URLSearchParams();
  searchParams.set('returnTo', returnTo.trim());
  return `/findings/${encodedId}?${searchParams.toString()}`;
}

export function activeTabForPath(pathname: string): AppTab {
  if (pathname.startsWith('/exposure')) return 'exposure';
  if (pathname.startsWith('/findings')) return 'findings';
  if (pathname.startsWith('/fix-intelligence')) return 'fix-intelligence';
  if (pathname.startsWith('/policies')) return 'policies';
  if (pathname.startsWith('/operations')) return 'operations';
  if (pathname.startsWith('/vulnerability-intelligence')) return 'vuln-repo';
  if (pathname.startsWith('/vuln-repo/campaigns')) return 'campaigns';
  if (pathname.startsWith('/vuln-repo')) return 'vuln-repo';
  if (pathname.startsWith('/inventory/ai')) return 'ai';
  if (pathname.startsWith('/inventory')) return 'inventory';
  if (pathname.startsWith('/end-of-life')) return 'end-of-life';
  if (pathname.startsWith('/connect')) return 'connect';
  if (pathname.startsWith('/admin')) return 'admin';
  if (pathname.startsWith('/platform/eol')) return 'end-of-life';
  if (pathname.startsWith('/platform/ai-policies')) return 'platform-policies';
  if (pathname.startsWith('/platform')) return 'platform';
  if (pathname.startsWith('/configurations')) return 'configurations';
  return 'dashboard';
}

export function titleForTab(tab: AppTab): string {
  switch (tab) {
    case 'exposure':
      return 'Exposure';
    case 'dashboard':
      return 'Overview';
    case 'findings':
      return 'Findings';
    case 'fix-intelligence':
      return 'Fix Intelligence';
    case 'policies':
      return 'AI Policies';
    case 'platform-policies':
      return 'Policy Distribution';
    case 'operations':
      return 'Operational Dashboard';
    case 'vuln-repo':
      return 'Vulnerability Repository';
    case 'campaigns':
      return 'Campaigns';
    case 'inventory':
      return 'Inventory';
    case 'ai':
      return 'AI Inventory';
    case 'end-of-life':
      return 'End-of-Life';
    case 'connect':
      return 'Connectors';
    case 'admin':
      return 'Administration';
    case 'platform':
      return 'Tenant Management';
    case 'configurations':
      return 'Configurations';
  }
}

export function buildLegacyCompatiblePath(search: string): string | null {
  const params = new URLSearchParams(search);
  const tab = params.get('tab');
  const inventoryView = params.get('inventoryView');
  const operationsView = params.get('operationsView');
  const vulnIntelView = params.get('vulnIntelView');
  const vulnRepoView = params.get('vulnRepoView');
  const connectView = params.get('connectView');
  const cveId = params.get('cveId');

  if (!tab && !inventoryView && !operationsView && !vulnIntelView && !vulnRepoView && !connectView && !cveId) {
    return null;
  }

  let nextPath = '/';
  if (tab === 'findings') {
    nextPath = '/findings';
  } else if (tab === 'operations') {
    nextPath = pathForOperationsView(normalizeOperationsRouteView(operationsView));
  } else if (tab === 'vulnerability-intelligence') {
    const normalizedView = vulnIntelView === 'vulnerabilities'
      ? 'vulnerabilities'
      : vulnIntelView === 'org-cves'
        ? 'org-cves'
        : 'vulnerabilities';
    nextPath = pathForVulnRepoView(normalizedView, cveId);
  } else if (tab === 'vuln-repo') {
    const normalizedView = vulnRepoView === 'vulnerabilities'
      ? 'vulnerabilities'
      : vulnRepoView === 'campaigns'
        ? 'campaigns'
      : vulnRepoView === 'end-of-life' || vulnRepoView === 'eol'
        ? 'end-of-life'
      : vulnRepoView === 'org-cves'
        ? 'org-cves'
        : 'dashboard';
    nextPath = pathForVulnRepoView(normalizedView, cveId);
  } else if (tab === 'inventory' || tab === 'assets') {
    nextPath = pathForInventoryView(normalizeInventoryRouteView(inventoryView));
  } else if (tab === 'connect' || tab === 'ingestion' || tab === 'sources') {
    nextPath = pathForConnectView(normalizeConnectRouteView(connectView));
  } else if (tab === 'admin' || tab === 'users' || tab === 'identity') {
    nextPath = '/admin/users';
  } else if (tab === 'platform') {
    nextPath = pathForPlatformView(PLATFORM_DEFAULT_VIEW);
  } else if (tab === 'configurations') {
    nextPath = pathForConfigurationsView(CONFIGURATIONS_DEFAULT_VIEW);
  } else if (tab === 'end-of-life') {
    nextPath = pathForPlatformView('eol');
  }

  ['tab', 'inventoryView', 'operationsView', 'vulnIntelView', 'vulnRepoView', 'connectView', 'cveId'].forEach((key) => params.delete(key));
  const nextSearch = params.toString();
  return nextSearch ? `${nextPath}?${nextSearch}` : nextPath;
}
