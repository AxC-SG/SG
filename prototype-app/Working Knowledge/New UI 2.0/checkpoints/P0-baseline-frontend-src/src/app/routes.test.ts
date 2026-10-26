import { describe, expect, it } from 'vitest';
import {
  activeTabForPath,
  appendSearchToPath,
  buildLegacyCompatiblePath,
  normalizePlatformRouteView,
  pathForConnectView,
  pathForInventoryViewWithSearch,
  pathForOperationsView,
  pathForTab,
  pathForVulnRepoView
} from './routes';

describe('routes', () => {
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
