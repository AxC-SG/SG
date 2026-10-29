import { describe, expect, it } from 'vitest';
import {
  activeTabForPath,
  appendSearchToPath,
  buildLegacyCompatiblePath,
  navDestinationForPath,
  normalizePlatformRouteView,
  pathForConnectView,
  pathForInventoryViewWithSearch,
  pathForOperationsView,
  pathForTab,
  pathForVulnRepoView,
  routeTitleForPath
} from './routes';

describe('routes', () => {
  it.each([
    ['/exposure', 'exposure'],
    ['/findings', 'vulnerability-findings'],
    ['/findings/F-10420', 'vulnerability-findings'],
    ['/findings/ai', 'ai-findings'],
    ['/findings/ai/vulnerabilities', 'ai-findings'],
    ['/findings/ai/exposures/exposure-1', 'ai-findings'],
    ['/vuln-repo/campaigns', 'campaigns'],
    ['/vuln-repo/campaigns/campaign-1', 'campaigns'],
    ['/fix-intelligence/all', 'fix-intelligence'],
    ['/fix-intelligence/details/fix-1', 'fix-intelligence'],
    ['/vuln-repo', 'vuln-repo'],
    ['/vuln-repo/vulnerabilities', 'vuln-repo'],
    ['/vuln-repo/org-cves', 'vuln-repo'],
    ['/vuln-repo/org-cves/CVE-2024-0001', 'vuln-repo'],
    ['/vuln-repo/org-cves/CVE-2024-0001/assets', 'vuln-repo'],
    ['/vuln-repo/org-cves/CVE-2024-0001/software', 'vuln-repo'],
    ['/vuln-repo/host-assets/host-1', 'vuln-repo'],
    ['/vuln-repo/software-assets', 'vuln-repo'],
    ['/vuln-repo/intel/CVE-2024-0001', 'vuln-repo'],
    ['/vulnerability-intelligence/org-cves/CVE-2024-0001', 'vuln-repo'],
    ['/inventory', 'inventory'],
    ['/inventory/cloud-resources', 'inventory'],
    ['/inventory/hosts/host-1', 'inventory'],
    ['/inventory/ai', 'ai-inventory'],
    ['/inventory/ai/declared-resources/resource-1', 'ai-inventory'],
    ['/policies/policy-1', 'policies'],
    ['/connect/copilot-studio', 'connect'],
    ['/configurations/triage', 'configurations'],
    ['/admin/audit', 'admin'],
    ['/platform/tenants', 'platform'],
    ['/platform/eol', 'end-of-life'],
    ['/platform/ai-policies/policy-1', 'platform-policies'],
    ['/platform/operations', 'platform-operations'],
    ['/authorized-workspaces', null],
    ['/findingsx', null],
  ])('selects one sidebar destination for %s', (pathname, expected) => {
    expect(navDestinationForPath(pathname)).toBe(expected);
  });

  it('gives every shell route a fallback title', () => {
    expect(routeTitleForPath('/exposure')).toBe('Exposure Dashboard');
    expect(routeTitleForPath('/findings/F-1')).toBe('Vulnerability Findings');
    expect(routeTitleForPath('/findings/ai/finding-1')).toBe('AI Findings');
    expect(routeTitleForPath('/vuln-repo/campaigns/c-1')).toBe('Campaigns');
    expect(routeTitleForPath('/fix-intelligence/details/fix-1')).toBe('Fix Intelligence');
    expect(routeTitleForPath('/vuln-repo/org-cves/CVE-1')).toBe('Vulnerability Repository');
    expect(routeTitleForPath('/inventory/ai/agents')).toBe('AI Inventory');
    expect(routeTitleForPath('/policies')).toBe('Policies');
    expect(routeTitleForPath('/admin/users')).toBe('Tenant Administration');
    expect(routeTitleForPath('/platform/tenants')).toBe('Tenant Management');
    expect(routeTitleForPath('/platform/vuln-intel')).toBe('Vulnerability Intelligence');
    expect(routeTitleForPath('/platform/operations')).toBe('Operations');
    expect(routeTitleForPath('/platform/eol')).toBe('End-of-Life');
    expect(routeTitleForPath('/platform/ai-policies')).toBe('Policy Distribution');
    expect(routeTitleForPath('/authorized-workspaces')).toBe('Authorized Workspaces');
    expect(routeTitleForPath('/')).toBe('Overview');
  });

  it('maps top-level tabs to canonical paths', () => {
    expect(pathForTab('dashboard')).toBe('/');
    expect(pathForTab('operations')).toBe('/operations/pipeline');
    expect(pathForTab('campaigns')).toBe('/vuln-repo/campaigns');
    expect(pathForTab('inventory')).toBe('/inventory');
    expect(pathForTab('end-of-life')).toBe('/platform/eol');
    expect(pathForTab('admin')).toBe('/admin/users');
    expect(pathForTab('platform')).toBe('/platform/tenants');
    expect(pathForConnectView('run-history')).toBe('/connect/run-history');
    expect(pathForOperationsView('platform-health')).toBe('/operations/platform-health');
    expect(pathForVulnRepoView('campaigns')).toBe('/vuln-repo/campaigns');
    expect(pathForVulnRepoView('end-of-life')).toBe('/platform/eol');
  });

  it('appends query-string filters for inventory drilldowns', () => {
    expect(pathForInventoryViewWithSearch('sbom', {
      sourceSystem: ['github', 'api'],
      ecosystem: 'maven',
      query: 'log4j',
      ignored: ''
    })).toBe('/inventory/sbom?sourceSystem=github&sourceSystem=api&ecosystem=maven&query=log4j');

    expect(appendSearchToPath('/operations/quality', {
      domain: 'EOL',
      focus: 'eol-mapping-review',
      empty: null
    })).toBe('/operations/quality?domain=EOL&focus=eol-mapping-review');
  });

  it('infers the active navigation tab from the route path', () => {
    expect(activeTabForPath('/')).toBe('dashboard');
    expect(activeTabForPath('/findings')).toBe('findings');
    expect(activeTabForPath('/operations/platform-health')).toBe('operations');
    expect(activeTabForPath('/vuln-repo/campaigns')).toBe('campaigns');
    expect(activeTabForPath('/inventory/hosts')).toBe('inventory');
    expect(activeTabForPath('/platform/eol')).toBe('end-of-life');
    expect(activeTabForPath('/connect/sources')).toBe('connect');
    expect(activeTabForPath('/admin/users')).toBe('admin');
    expect(activeTabForPath('/platform/feeds')).toBe('platform');
  });

  it('redirects legacy operations deep links to canonical routes', () => {
    expect(buildLegacyCompatiblePath('?tab=operations&operationsView=api-read-path&foo=bar')).toBe(
      '/operations/platform-health?foo=bar'
    );
    expect(buildLegacyCompatiblePath('?tab=operations&operationsView=ai&capability=NORMALIZATION_IDENTITY_ASSIGNMENT')).toBe(
      '/operations/pipeline?capability=NORMALIZATION_IDENTITY_ASSIGNMENT'
    );
  });

  it('redirects legacy vulnerability intelligence deep links to canonical routes', () => {
    expect(buildLegacyCompatiblePath('?tab=vulnerability-intelligence&vulnIntelView=org-cves&cveId=CVE-2026-1234')).toBe(
      '/vuln-repo/org-cves/CVE-2026-1234'
    );
    expect(buildLegacyCompatiblePath('?tab=vulnerability-intelligence')).toBe('/vuln-repo/vulnerabilities');
    expect(buildLegacyCompatiblePath('?tab=vuln-repo&vulnRepoView=campaigns')).toBe('/vuln-repo/campaigns');
    expect(buildLegacyCompatiblePath('?tab=vuln-repo&vulnRepoView=end-of-life')).toBe('/platform/eol');
    expect(buildLegacyCompatiblePath('?tab=end-of-life')).toBe('/platform/eol');
  });

  it('redirects legacy inventory and connect deep links while preserving non-routing params', () => {
    expect(buildLegacyCompatiblePath('?tab=inventory&inventoryView=host-review-queue&reviewCategory=MISSING_VERSION')).toBe(
      '/inventory/hosts?reviewCategory=MISSING_VERSION'
    );
    expect(buildLegacyCompatiblePath('?tab=inventory&inventoryView=applications&sourceSystem=github')).toBe(
      '/inventory/sbom?sourceSystem=github'
    );
    expect(buildLegacyCompatiblePath('?tab=inventory&inventoryView=image-inventory&ecosystem=oci')).toBe(
      '/inventory/container-images?ecosystem=oci'
    );
    expect(buildLegacyCompatiblePath('?tab=connect&connectView=integration-queue&source=ghsa')).toBe(
      '/connect/run-history?source=ghsa'
    );
  });

  it('returns null when the URL does not contain legacy navigation state', () => {
    expect(buildLegacyCompatiblePath('?page=1&size=25')).toBeNull();
  });

  it('falls back to the default platform console view for removed platform connector routes', () => {
    expect(normalizePlatformRouteView('connectors')).toBe('tenants');
  });

  it('normalizes the platform EOL view', () => {
    expect(normalizePlatformRouteView('eol')).toBe('eol');
  });
});
