// Representative routes per presentation family, shared by the visual spec, the affected-route
// runner and e2e/affected-routes.json. `who` selects the fixture actor: tenant, platform or
// signedOut (auth entry and public pages).
import { APPROVED_PLATFORM_POLICY_ID, PRIMARY_POLICY_ID } from './governance-fixtures.mjs';
import { PRIMARY_CVE } from './cve-fixtures.mjs';
import { PRIMARY_AI_ASSET_ID, PRIMARY_HOST_ID, PRIMARY_SOFTWARE_IDENTITY_ID } from './inventory-fixtures.mjs';
import { PRIMARY_CAMPAIGN_ID } from './experience-fixtures.mjs';
import { PRIMARY_FIX_ID } from './fix-fixtures.mjs';

export const FAMILY_ROUTES = {
  findings: [['/findings', 'tenant'], ['/findings/F-10420', 'tenant'], ['/findings/ai', 'tenant'], ['/findings/ai/vulnerabilities', 'tenant'], ['/findings/ai/exposures', 'tenant']],
  cve: [['/vuln-repo/org-cves', 'tenant'], [`/vuln-repo/org-cves/${PRIMARY_CVE}`, 'tenant'], [`/vuln-repo/org-cves/${PRIMARY_CVE}/assets`, 'tenant'], ['/vuln-repo/vulnerabilities', 'tenant']],
  inventory: [['/inventory', 'tenant'], ['/inventory/hosts', 'tenant'], [`/inventory/hosts/${PRIMARY_HOST_ID}`, 'tenant'], [`/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`, 'tenant'], ['/inventory/ai', 'tenant'], [`/inventory/ai/${PRIMARY_AI_ASSET_ID}`, 'tenant'], ['/inventory/cloud-resources', 'tenant']],
  governance: [['/policies', 'tenant'], [`/policies/${PRIMARY_POLICY_ID}`, 'tenant'], ['/platform/ai-policies', 'platform'], [`/platform/ai-policies/${APPROVED_PLATFORM_POLICY_ID}`, 'platform']],
  connect: [['/connect', 'tenant'], ['/connect/run-history', 'tenant'], ['/connect?connectSource=servicenow-cmdb', 'tenant'], ['/connect?connectSource=patch-sccm', 'tenant']],
  experience: [['/exposure', 'tenant'], ['/vuln-repo', 'tenant'], ['/vuln-repo/campaigns', 'tenant'], [`/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`, 'tenant'], ['/admin/users', 'tenant'], ['/configurations/sla', 'tenant'], ['/platform/tenants', 'platform'], ['/platform/operations', 'platform']],
  fix: [['/fix-intelligence/all', 'tenant'], ['/fix-intelligence/patches', 'tenant'], ['/fix-intelligence/workarounds', 'tenant'], ['/fix-intelligence/compensating-controls', 'tenant'], ['/fix-intelligence/details/fix-smbv1', 'tenant'], [`/fix-intelligence/details/${PRIMARY_FIX_ID}`, 'tenant']],
  auth: [['/login', 'signedOut'], ['/setup', 'signedOut']],
  public: [['/demo', 'signedOut'], ['/demo/blog', 'signedOut'], ['/demo/request', 'signedOut']],
};

export const ALL_ROUTES = Object.values(FAMILY_ROUTES).flat();

/** Looks up the actor for a route path; unknown paths default to the tenant actor. */
export function routeEntry(path) {
  return ALL_ROUTES.find(([candidate]) => candidate === path) ?? [path, 'tenant'];
}
