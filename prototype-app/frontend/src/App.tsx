import React from 'react';
import { RouteErrorBoundary } from './components/RouteErrorBoundary';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { PerformanceInstrumentation } from './lib/performanceMonitoring';
import type { InventoryViewKey } from './features/inventory/types';
import { AI_ARTIFACT_CATEGORIES, legacyAgentRosterRedirect, combinedNativeKindFilterValue } from './features/ai-security/categories';
import type { AdminRouteView, AppTab, ConfigurationsRouteView, ConnectRouteView, FixIntelligenceRouteView, VulnerabilityIntelRouteView } from './app/routes';
import { FIX_VIEWS } from './features/fix-intelligence/format';
import {
  activeTabForPath,
  normalizeFixIntelligenceRouteView,
  pathForFixIntelligenceView,
  buildLegacyCompatiblePath,
  normalizeAdminRouteView,
  normalizeConfigurationsRouteView,
  normalizeConnectRouteView,
  normalizeInventoryRouteView,
  normalizeOperationsRouteView,
  normalizePlatformRouteView,
  pathForAdminView,
  pathForAiBomDeclaredResources,
  pathForAiFindings,
  pathForAiInventoryOverview,
  pathForConfigurationsView,
  pathForConnectView,
  pathForInventoryView,
  pathForInventoryAiAgents,
  pathForPlatformView,
  pathForTab,
  pathForVulnRepoView,
  titleForTab
} from './app/routes';
import { api, ApiError, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken, type TestPersona } from './api/client';
import { ActorContextState, useActor } from './features/auth/context';
import { useActorQuery } from './features/auth/queries';
import { canUseEntitlement } from './features/auth/entitlements';
import type { ActorContext } from './features/auth/types';
import {
  canAccessPlatformConsole,
  canManageInventorySources,
  canManageRiskPolicy,
  canManageTenant,
  canManageUsers,
  canRunSecurityWorkflow,
  canViewReadOnly
} from './features/auth/roles';

const ExposureDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/ExposureDashboardPage')).ExposureDashboardPage
}));
const FindingsPage = React.lazy(async () => ({
  default: (await import('./pages/FindingsPage')).FindingsPage
}));
const FixIntelligencePage = React.lazy(async () => ({
  default: (await import('./features/fix-intelligence/FixIntelligencePage')).FixIntelligencePage
}));
const FixDetailPage = React.lazy(async () => ({
  default: (await import('./features/fix-intelligence/FixDetailPage')).FixDetailPage
}));
const AiFindingsPage = React.lazy(async () => ({
  default: (await import('./pages/AiFindingsPage')).AiFindingsPage
}));
const AiFindingDetailPage = React.lazy(async () => ({
  default: (await import('./pages/AiFindingDetailPage')).AiFindingDetailPage
}));
const AiExposuresPage = React.lazy(async () => ({
  default: (await import('./pages/AiExposuresPage')).AiExposuresPage
}));
const AiPoliciesPage = React.lazy(async () => ({
  default: (await import('./pages/AiPoliciesPage')).AiPoliciesPage
}));
const AiPolicyDetailPage = React.lazy(async () => ({
  default: (await import('./pages/AiPolicyDetailPage')).AiPolicyDetailPage
}));
const PlatformAiPolicyDetailPage = React.lazy(async () => ({
  default: (await import('./pages/PlatformAiPolicyDetailPage')).PlatformAiPolicyDetailPage
}));
const AiInventoryPage = React.lazy(async () => ({
  default: (await import('./pages/AiInventoryPage')).AiInventoryPage
}));
const AiInventoryAssetsPage = React.lazy(async () => ({
  default: (await import('./pages/AiInventoryAssetsPage')).AiInventoryAssetsPage
}));
const AiKnowledgeMcpInventoryPage = React.lazy(async () => ({
  default: (await import('./pages/AiKnowledgeMcpInventoryPage')).AiKnowledgeMcpInventoryPage
}));
const AiAssetDetailPage = React.lazy(async () => ({
  default: (await import('./pages/AiAssetDetailPage')).AiAssetDetailPage
}));
const AiBomDeclaredResourcesPage = React.lazy(async () => ({
  default: (await import('./pages/AiBomDeclaredResourcesPage')).AiBomDeclaredResourcesPage
}));
const AiBomDeclaredResourceDetailPage = React.lazy(async () => ({
  default: (await import('./pages/AiBomDeclaredResourceDetailPage')).AiBomDeclaredResourceDetailPage
}));
const CopilotStudioConnectorPage = React.lazy(async () => ({
  default: (await import('./pages/CopilotStudioConnectorPage')).CopilotStudioConnectorPage
}));
const FindingDetailPage = React.lazy(async () => ({
  default: (await import('./pages/FindingDetailPage')).FindingDetailPage
}));
const OperationalDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/OperationalDashboardPage')).OperationalDashboardPage
}));
const VulnRepoDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoDashboardPage')).VulnRepoDashboardPage
}));
const PlatformVulnIntelDetailPage = React.lazy(async () => ({
  default: (await import('./pages/PlatformVulnIntelDetailPage')).PlatformVulnIntelDetailPage
}));
const VulnRepoVulnerabilitiesPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoVulnerabilitiesPage')).VulnRepoVulnerabilitiesPage
}));
const CampaignsPage = React.lazy(async () => ({
  default: (await import('./pages/CampaignsPage')).CampaignsPage
}));
const CampaignDetailPage = React.lazy(async () => ({
  default: (await import('./features/campaigns/CampaignDetailPage')).CampaignDetailPage
}));
const VulnRepoOrgCvePage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoOrgCvePage')).VulnRepoOrgCvePage
}));
const VulnRepoCveAssetsPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoCveAssetsPage')).VulnRepoCveAssetsPage
}));
const VulnRepoCveSoftwarePage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoCveSoftwarePage')).VulnRepoCveSoftwarePage
}));
const VulnRepoSoftwareAssetsPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoSoftwareAssetsPage')).VulnRepoSoftwareAssetsPage
}));
const HostAssetDetailPage = React.lazy(async () => ({
  default: (await import('./pages/HostAssetDetailPage')).HostAssetDetailPage
}));
const InventoryPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryPage')).InventoryPage
}));
const CloudResourcesPage = React.lazy(async () => ({
  default: (await import('./pages/CloudResourcesPage')).CloudResourcesPage
}));
const InventoryComponentViewsPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryComponentViewsPage')).InventoryComponentViewsPage
}));
const InventoryOverviewPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryOverviewPage')).InventoryOverviewPage
}));
const SoftwareIdentitiesPage = React.lazy(async () => ({
  default: (await import('./pages/SoftwareIdentitiesPage')).SoftwareIdentitiesPage
}));
const BomInventoryPage = React.lazy(async () => ({
  default: (await import('./pages/BomInventoryPage')).BomInventoryPage
}));
const ApplicationsDashboard = React.lazy(async () => ({
  default: (await import('./features/inventory/ApplicationsDashboard')).ApplicationsDashboard
}));
// MOCKS — replace with real page imports when implementing
const BomComponents = React.lazy(async () => ({
  default: (await import('./features/inventory/BomComponents')).BomComponents
}));
const SoftwareIdentityDetailPage = React.lazy(async () => ({
  default: (await import('./pages/SoftwareIdentityDetailPage')).SoftwareIdentityDetailPage
}));
const ConnectPage = React.lazy(async () => ({
  default: (await import('./pages/ConnectPage')).ConnectPage
}));
const ConfigurationsPage = React.lazy(async () => ({
  default: (await import('./pages/ConfigurationsPage')).ConfigurationsPage
}));
const UserManagementPage = React.lazy(async () => ({
  default: (await import('./pages/UserManagementPage')).UserManagementPage
}));
const PlatformConsolePage = React.lazy(async () => ({
  default: (await import('./pages/PlatformConsolePage')).PlatformConsolePage
}));
const AuthorizedWorkspacesPage = React.lazy(async () => ({
  default: (await import('./pages/AuthorizedWorkspacesPage')).AuthorizedWorkspacesPage
}));
const DemoLandingPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoLandingPage
}));
const BlogIndexPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).BlogIndexPage
}));
const ZeroDayBlogPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).ZeroDayBlogPage
}));
const MythosReadinessBlogPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).MythosReadinessBlogPage
}));
const SbomExploitabilityBlogPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).SbomExploitabilityBlogPage
}));
const DemoRequestPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoRequestPage
}));
const DemoRequestSuccessPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoRequestSuccessPage
}));
const DemoInvitePage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoInvitePage
}));
const TenantInvitePage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).TenantInvitePage
}));
const SetupSessionPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).SetupSessionPage
}));
const LoginPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).LoginPage
}));
const DemoExpiredPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoExpiredPage
}));

type Theme = 'light' | 'dark';
type TestPersonaMode = 'backend' | 'preview';
type ActiveTestPersona = {
  mode: TestPersonaMode;
  persona: TestPersona;
};

type TestPersonaControls = {
  enabled: boolean;
  personas: TestPersona[];
  activePersona: ActiveTestPersona | null;
  loading: boolean;
  error: string | null;
  loadPersonas: () => void;
  impersonateBackend: (persona: TestPersona) => void;
  previewPersona: (persona: TestPersona) => void;
  resetPersona: () => void;
};

const THEME_STORAGE_KEY = 'scoutai-theme';
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';
const TEST_PERSONA_PREVIOUS_TOKEN_KEY = 'vulnwatch.testPersona.previousToken';
const EMPTY_TEST_PERSONA_CONTROLS: TestPersonaControls = {
  enabled: false,
  personas: [],
  activePersona: null,
  loading: false,
  error: null,
  loadPersonas: () => undefined,
  impersonateBackend: () => undefined,
  previewPersona: () => undefined,
  resetPersona: () => undefined
};
const TestPersonaControlsState = React.createContext<TestPersonaControls>(EMPTY_TEST_PERSONA_CONTROLS);
const BOTTOM_NAV_TABS: AppTab[] = [];
const INVENTORY_PILL_ORDER: Array<{ key: InventoryViewKey; label: string; countKey?: 'hosts' | 'software' | 'containerImages' | 'applications' | 'bomInventory' }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'hosts', label: 'Hosts', countKey: 'hosts' },
  { key: 'cloud-resources', label: 'Cloud Resources' },
  { key: 'software-identities', label: 'Software Entities', countKey: 'software' },
  { key: 'container-images', label: 'Container Images', countKey: 'containerImages' },
  { key: 'sbom', label: 'Applications', countKey: 'applications' },
  { key: 'bom-components', label: 'BOM Components', countKey: 'bomInventory' },
  { key: 'bom-inventory', label: 'BOM Inventory', countKey: 'bomInventory' }
];
type AiInventoryNavItem = { key: string; label: string; nativeKind?: string };

const AI_INVENTORY_NAV_ITEMS: AiInventoryNavItem[] = [
  { key: 'overview', label: 'Overview' },
  ...AI_ARTIFACT_CATEGORIES.map((category) => ({ key: category.key, label: category.label, nativeKind: combinedNativeKindFilterValue(category.nativeKinds) })),
  { key: 'mcp-servers', label: 'MCP Servers' },
  { key: 'data-stores', label: 'Data stores' },
  { key: 'others', label: 'Others' },
];
const VULN_REPO_NAV_ITEMS: Array<{ key: VulnerabilityIntelRouteView; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'vulnerabilities', label: 'Intelligence' },
];
const ADMIN_PILL_ORDER: Array<{ key: AdminRouteView; label: string }> = [
  { key: 'users', label: 'Users' },
  { key: 'invites', label: 'Invites' },
  { key: 'roles', label: 'Roles & Permissions' },
  { key: 'service-accounts', label: 'Service Accounts' },
  { key: 'audit', label: 'Audit' }
];
const CONFIGURATIONS_PILL_ORDER: Array<{ key: ConfigurationsRouteView; label: string }> = [
  { key: 'sla', label: 'SLA & Remediation' },
  { key: 'triage', label: 'S.AI Prioritization' },
  { key: 'automation', label: 'Workflow Automation' },
  { key: 'ownership', label: 'Ownership' },
  { key: 'findings-score', label: 'Findings Score' },
  { key: 'suppress', label: 'Suppression Rules' },
  { key: 'auto-findings', label: 'Auto Investigation & Findings' }
];

function getInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === 'light' || saved === 'dark') {
    return saved;
  }
  return 'dark';
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M9.7 3.4h4.6l.5 2.4c.5.2 1 .4 1.4.8l2.3-.8 2.3 4-1.8 1.6v1.2l1.8 1.6-2.3 4-2.3-.8c-.4.3-.9.6-1.4.8l-.5 2.4H9.7l-.5-2.4c-.5-.2-1-.5-1.4-.8l-2.3.8-2.3-4L5 12.6v-1.2L3.2 9.8l2.3-4 2.3.8c.4-.3.9-.6 1.4-.8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function LegacyQueryRedirect() {
  const location = useLocation();
  const navigate = useNavigate();

  React.useEffect(() => {
    if (location.pathname !== '/') {
      return;
    }
    const nextPath = buildLegacyCompatiblePath(location.search);
    if (nextPath && nextPath !== `${location.pathname}${location.search}`) {
      navigate(nextPath, { replace: true });
    }
  }, [location.pathname, location.search, navigate]);

  return null;
}

function defaultPathForActor(actor: ActorContext | null): string {
  if (!actor) {
    return '/exposure';
  }
  if (actor.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER') && actor.platformScope) {
    return '/platform/tenants';
  }
  if (canManageRiskPolicy(actor)) {
    return '/configurations';
  }
  return '/exposure';
}

function HomeRoute() {
  const actor = useActor();
  return <Navigate to={defaultPathForActor(actor)} replace />;
}

function ExposureDashboardRoute() {
  return <ExposureDashboardPage />;
}


function FixIntelligenceRoute() {
  const { view } = useParams();
  const normalized = normalizeFixIntelligenceRouteView(view);
  if (view !== normalized) return <Navigate to={pathForFixIntelligenceView(normalized)} replace />;
  return <FixIntelligencePage view={normalized} />;
}

function FindingsRoute() {
  const navigate = useNavigate();
  return (
    <FindingsPage
      onOpenCveWorkbench={(vulnerabilityId) => navigate(pathForVulnRepoView('org-cves', vulnerabilityId))}
    />
  );
}


function AiSecurityRoute({ children }: { children: React.ReactNode }) {
  const actor = useActor();
  const location = useLocation();
  const legacyPath = location.pathname === '/inventory/ai/agent-versions'
    ? legacyAgentRosterRedirect(location.search + (location.search ? '&' : '?') + 'view=agent-versions')
    : ['/inventory/ai', '/inventory/ai/assets', '/inventory/ai/overview'].includes(location.pathname)
      ? legacyAgentRosterRedirect(location.search) : null;
  if (!canUseEntitlement(actor, 'ai.security') || actor?.platformScope) {
    return <Navigate to="/exposure" replace />;
  }
  if (legacyPath) return <Navigate to={legacyPath} replace />;
  return <>{children}</>;
}

function FindingDetailRoute() {
  const params = useParams<{ displayId?: string }>();
  const displayId = params.displayId ? decodeURIComponent(params.displayId) : null;
  if (!displayId) {
    return <Navigate to="/findings" replace />;
  }
  return <FindingDetailPage key={displayId} findingRef={displayId} />;
}

function AiFindingDetailRoute() {
  const params = useParams<{ findingId?: string }>();
  const findingId = params.findingId ? decodeURIComponent(params.findingId) : null;
  if (!findingId) {
    return <Navigate to={pathForAiFindings()} replace />;
  }
  return <AiSecurityRoute><AiFindingDetailPage findingId={findingId} /></AiSecurityRoute>;
}

function AiBomDeclaredResourceDetailRoute() {
  const params = useParams<{ resourceId?: string }>();
  const resourceId = params.resourceId ? decodeURIComponent(params.resourceId) : null;
  if (!resourceId) {
    return <Navigate to={pathForAiBomDeclaredResources()} replace />;
  }
  return <AiSecurityRoute><AiBomDeclaredResourceDetailPage resourceId={resourceId} /></AiSecurityRoute>;
}

function AiPolicyDetailRoute() {
  const params = useParams<{ policyId?: string }>();
  const policyId = params.policyId ? decodeURIComponent(params.policyId) : null;
  if (!policyId) return <Navigate to="/policies" replace />;
  return <AiPolicyDetailPage policyId={policyId} />;
}

function PlatformAiPolicyDetailRoute() {
  const params = useParams<{ policyId?: string }>();
  const policyId = params.policyId ? decodeURIComponent(params.policyId) : null;
  if (!policyId) return <Navigate to="/platform/ai-policies" replace />;
  return <PlatformAiPolicyDetailPage policyId={policyId} />;
}

function OperationsRoute() {
  const params = useParams<{ operationsView?: string }>();
  const location = useLocation();
  const actor = useActor();
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;

  if (platformScopeOwner) {
    return (
      <Navigate
        to={pathForPlatformView('eol')}
        replace
        state={{ platformMessage: 'Operations is no longer part of the platform view. Use EOL from the platform console.' }}
      />
    );
  }

  return <OperationalDashboardPage selectedView={normalizeOperationsRouteView(params.operationsView)} redirectSearch={location.search} />;
}

function LegacyVulnerabilityIntelVulnerabilitiesRoute() {
  const location = useLocation();
  return <Navigate to={`${pathForVulnRepoView('vulnerabilities')}${location.search}`} replace />;
}

function LegacyVulnerabilityIntelWorkbenchRoute() {
  const location = useLocation();
  const params = useParams<{ cveId?: string }>();
  return <Navigate to={`${pathForVulnRepoView('org-cves', params.cveId)}${location.search}`} replace />;
}

function VulnRepoDashboardRoute() {
  return <VulnRepoDashboardPage />;
}

function VulnRepoWorkbenchRoute() {
  const navigate = useNavigate();
  const location = useLocation();
  const params = useParams<{ cveId?: string }>();
  const hasOpenedDirectRecordRef = React.useRef(false);
  const returnTo = typeof location.state === 'object' && location.state && 'returnTo' in location.state
    ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
    : '';
  return (
    <VulnRepoOrgCvePage
      initialCveId={params.cveId}
      returnTo={returnTo || undefined}
      onSelectedCveChange={(cveId) => {
        if (cveId) {
          hasOpenedDirectRecordRef.current = true;
          if (params.cveId !== cveId) {
            navigate(pathForVulnRepoView('org-cves', cveId), { replace: true });
          }
          return;
        }
        if (params.cveId && hasOpenedDirectRecordRef.current) {
          navigate(pathForVulnRepoView('org-cves'), { replace: true });
        }
      }}
    />
  );
}

function VulnRepoHostAssetRoute() {
  const params = useParams<{ assetId?: string }>();
  const assetId = params.assetId ? decodeURIComponent(params.assetId) : null;

  if (!assetId) {
    return <Navigate to={pathForVulnRepoView('dashboard')} replace />;
  }

  return <HostAssetDetailPage assetId={assetId} />;
}

function InventoryHostAssetRoute() {
  const params = useParams<{ assetId?: string }>();
  const assetId = params.assetId ? decodeURIComponent(params.assetId) : null;

  if (!assetId) {
    return <Navigate to={pathForInventoryView('hosts')} replace />;
  }

  return <HostAssetDetailPage assetId={assetId} />;
}

function InventoryAiAssetRoute() {
  const params = useParams<{ assetId?: string }>();
  const assetId = params.assetId ? decodeURIComponent(params.assetId) : null;

  if (!assetId) {
    return <Navigate to={pathForInventoryView('ai')} replace />;
  }

  return <AiSecurityRoute><AiAssetDetailPage artifactId={assetId} /></AiSecurityRoute>;
}

function SoftwareIdentityDetailRoute() {
  const params = useParams<{ softwareIdentityId?: string }>();
  const softwareIdentityId = params.softwareIdentityId ? decodeURIComponent(params.softwareIdentityId) : null;

  if (!softwareIdentityId) {
    return <Navigate to={pathForInventoryView('software-identities')} replace />;
  }

  return <SoftwareIdentityDetailPage softwareIdentityId={softwareIdentityId} />;
}

function InventoryRoute() {
  const params = useParams<{ inventoryView?: string }>();
  const selectedView = normalizeInventoryRouteView(params.inventoryView);
  if (selectedView === 'overview') {
    return <InventoryOverviewPage />;
  }
  if (selectedView === 'software-identities') {
    return <SoftwareIdentitiesPage />;
  }
  if (selectedView === 'hosts') {
    return <InventoryPage selectedView={selectedView} />;
  }
  if (selectedView === 'sbom') {
    return <ApplicationsDashboard />;
  }
  if (selectedView === 'bom-components') {
    return <BomComponents />;
  }
  if (selectedView === 'bom-inventory') {
    return <BomInventoryPage />;
  }
  if (selectedView === 'cloud-resources') {
    return <CloudResourcesPage />;
  }
  if (selectedView === 'ai') {
    return <AiSecurityRoute><AiInventoryPage /></AiSecurityRoute>;
  }
  return <InventoryComponentViewsPage selectedView={selectedView} />;
}

function ConnectRoute() {
  const navigate = useNavigate();
  const params = useParams<{ connectView?: string }>();
  return (
    <ConnectPage
      initialView={normalizeConnectRouteView(params.connectView)}
      onViewChange={(view: ConnectRouteView) => navigate(pathForConnectView(view), { replace: true })}
    />
  );
}

function EndOfLifeRoute() {
  const actor = useActor();
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;

  if (platformScopeOwner) {
    return <Navigate to={pathForPlatformView('eol')} replace />;
  }

  return <Navigate to={pathForTab('exposure')} replace />;
}

function PlatformRoute() {
  const actor = useActor();
  const params = useParams<{ platformView?: string }>();
  if (!canAccessPlatformConsole(actor)) {
    return (
      <section className="panel">
        <div className="notice error" role="alert">
          Platform console access requires the Platform Owner role.
        </div>
      </section>
    );
  }
  return <PlatformConsolePage selectedView={normalizePlatformRouteView(params.platformView)} />;
}

function AuthorizedWorkspacesRoute() {
  const actor = useActor();
  if (!actor?.roles.includes('PLATFORM_OWNER')) {
    return <Navigate to="/exposure" replace />;
  }
  return <AuthorizedWorkspacesPage />;
}

function AdminRoute() {
  const actor = useActor();
  if (!canManageTenant(actor)) {
    return <Navigate to="/exposure" replace />;
  }
  return <UserManagementPage />;
}

function routeLoadingFallback() {
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="notice">Loading page...</div>
      </section>
    </div>
  );
}

function PublicLandingRoute() {
  return (
    <React.Suspense fallback={routeLoadingFallback()}>
      <DemoLandingPage />
    </React.Suspense>
  );
}

function actorFromPersona(persona: TestPersona): ActorContext {
  const platformOwner = persona.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER');
  return {
    creator: platformOwner,
    principal: persona.subject,
    userId: persona.subject,
    tenantId: platformOwner ? null : persona.tenantSlug ? `preview:${persona.tenantSlug}` : null,
    tenantName: platformOwner ? null : persona.tenantName,
    roles: persona.roles,
    allowedTenants: !platformOwner && persona.tenantSlug && persona.tenantName ? [{
      id: `preview:${persona.tenantSlug}`,
      name: persona.tenantName,
      slug: persona.tenantSlug,
      role: persona.roles[0] ?? 'SECURITY_ANALYST'
    }] : [],
    platformScope: platformOwner,
    actingAsPlatformOwner: false,
    sensitiveActionConfirmationRequired: false,
    planCode: null,
    demo: false,
    demoExpiresAt: null,
    demoDaysRemaining: null,
    demoCapabilities: null,
    demoUsage: null
  };
}

function savePreviousAuthTokenForPersona(): void {
  if (typeof window === 'undefined' || window.localStorage.getItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY) != null) {
    return;
  }
  window.localStorage.setItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY, getStoredAuthToken());
}

function restorePreviousAuthTokenForPersona(): void {
  if (typeof window === 'undefined') {
    clearStoredAuthToken();
    return;
  }
  const previous = window.localStorage.getItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY);
  window.localStorage.removeItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY);
  if (previous && previous.trim().length > 0) {
    setStoredAuthToken(previous);
  } else {
    clearStoredAuthToken();
  }
}

function AuthSessionBoundary({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const isLocalDev = import.meta.env.VITE_LOCAL_DEV === 'true';

  // Hooks must be called unconditionally - always at top level
  const actorQuery = useActorQuery();
  const [personas, setPersonas] = React.useState<TestPersona[]>([]);
  const [personaLoading, setPersonaLoading] = React.useState(false);
  const [personaError, setPersonaError] = React.useState<string | null>(null);
  const [activePersona, setActivePersona] = React.useState<ActiveTestPersona | null>(null);
  const [previewActor, setPreviewActor] = React.useState<ActorContext | null>(null);

  const loadPersonas = React.useCallback(() => {
    if (!TEST_PERSONAS_ENABLED || personaLoading || personas.length > 0) {
      return;
    }
    setPersonaLoading(true);
    setPersonaError(null);
    api.listTestPersonas()
      .then(setPersonas)
      .catch((error) => setPersonaError(error instanceof Error ? error.message : 'Failed to load test personas'))
      .finally(() => setPersonaLoading(false));
  }, [personaLoading, personas.length]);

  const impersonateBackend = React.useCallback((persona: TestPersona) => {
    savePreviousAuthTokenForPersona();
    setPersonaLoading(true);
    setPersonaError(null);
    api.issueTestPersonaToken(persona.key)
      .then((response) => {
        setStoredAuthToken(response.token);
        setPreviewActor(null);
        setActivePersona({ mode: 'backend', persona: response.persona });
        return actorQuery.refetch();
      })
      .catch((error) => setPersonaError(error instanceof Error ? error.message : 'Failed to issue test persona token'))
      .finally(() => setPersonaLoading(false));
  }, [actorQuery]);

  const previewPersona = React.useCallback((persona: TestPersona) => {
    setPreviewActor(actorFromPersona(persona));
    setActivePersona({ mode: 'preview', persona });
    setPersonaError(null);
  }, []);

  const resetPersona = React.useCallback(() => {
    restorePreviousAuthTokenForPersona();
    setPreviewActor(null);
    setActivePersona(null);
    setPersonaError(null);
    void actorQuery.refetch();
  }, [actorQuery]);

  const personaControls = React.useMemo<TestPersonaControls>(() => ({
    enabled: TEST_PERSONAS_ENABLED,
    personas,
    activePersona,
    loading: personaLoading,
    error: personaError,
    loadPersonas,
    impersonateBackend,
    previewPersona,
    resetPersona
  }), [activePersona, impersonateBackend, loadPersonas, personaError, personaLoading, personas, previewPersona, resetPersona]);

  // LOCAL DEV MODE: Bypass auth entirely
  if (isLocalDev) {
    const devActorContext: ActorContext = {
      creator: true,
      principal: 'dev-admin',
      userId: 'dev-admin-uuid',
      tenantId: 'dev-tenant',
      tenantName: 'Dev Tenant',
      roles: ['ROLE_PLATFORM_OWNER', 'ROLE_TENANT_ADMIN', 'ROLE_SECURITY_ANALYST', 'ROLE_INVENTORY_ADMIN'],
      allowedTenants: [{ id: 'dev-tenant', name: 'Dev Tenant', slug: 'dev-tenant', role: 'ROLE_TENANT_ADMIN' }],
      platformScope: false,
      actingAsPlatformOwner: true,
      sensitiveActionConfirmationRequired: false,
      entitlements: { 'ai.security': true }
    };
    return (
      <TestPersonaControlsState.Provider value={{ enabled: false, personas: [], activePersona: null, loading: false, error: null, loadPersonas: () => {}, impersonateBackend: () => {}, previewPersona: () => {}, resetPersona: () => {} }}>
        <ActorContextState.Provider value={devActorContext}>
          {children}
        </ActorContextState.Provider>
      </TestPersonaControlsState.Provider>
    );
  }

  if (actorQuery.isLoading || actorQuery.isFetching && !actorQuery.data) {
    if (location.pathname === '/') {
      return <PublicLandingRoute />;
    }
    return routeLoadingFallback();
  }

  if (actorQuery.error instanceof ApiError && actorQuery.error.status === 401) {
    clearStoredAuthToken();
    return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  }

  if (!actorQuery.data) {
    if (location.pathname === '/') {
      return <PublicLandingRoute />;
    }
    return <div className="panel" role="alert">
      <p>Unable to verify your session. Please try again.</p>
      <button type="button" className="btn btn-primary" onClick={() => void actorQuery.refetch()}>Retry</button>
    </div>;
  }

  return (
    <TestPersonaControlsState.Provider value={personaControls}>
      <ActorContextState.Provider value={previewActor ?? actorQuery.data}>
        {children}
      </ActorContextState.Provider>
    </TestPersonaControlsState.Provider>
  );
}

function AppShell() {
  const actor = useActor();
  const testPersonas = React.useContext(TestPersonaControlsState);
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const [theme, setTheme] = React.useState<Theme>(() => getInitialTheme());
  const [navOpen, setNavOpen] = React.useState(false);
  const [settingsMenuOpen, setSettingsMenuOpen] = React.useState(false);
  const [personaDialogOpen, setPersonaDialogOpen] = React.useState(false);
  const [inventoryNavExpanded, setInventoryNavExpanded] = React.useState(false);
  const [aiInventoryNavExpanded, setAiInventoryNavExpanded] = React.useState(false);
  const [findingsNavExpanded, setFindingsNavExpanded] = React.useState(false);
  const [fixNavExpanded, setFixNavExpanded] = React.useState(false);
  const [adminNavExpanded, setAdminNavExpanded] = React.useState(false);
  const [configurationsNavExpanded, setConfigurationsNavExpanded] = React.useState(false);

  const activeTab = activeTabForPath(location.pathname);
  const pathSegments = location.pathname.split('/').filter(Boolean);
  const activeInventoryView = normalizeInventoryRouteView(pathSegments[1]);
  const activeAdminView = normalizeAdminRouteView(pathSegments[1]);
  const activeConfigurationsView = normalizeConfigurationsRouteView(pathSegments[1]);
  const vulnRepoSegment = location.pathname.startsWith('/vuln-repo')
    ? pathSegments[1]
    : null;
  const activeVulnRepoView = vulnRepoSegment === 'vulnerabilities'
    ? 'vulnerabilities'
    : vulnRepoSegment === 'campaigns'
      ? 'campaigns'
    : vulnRepoSegment === 'org-cves'
      ? 'org-cves'
    : 'dashboard';
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;
  const aiSecurityEnabled = canUseEntitlement(actor, 'ai.security') && !isPlatformScope;
  const visiblePrimaryNavTabs = React.useMemo(() => {
    if (platformScopeOwner) {
      return ['vuln-repo', 'connect', 'platform', 'end-of-life', 'platform-policies'] satisfies AppTab[];
    }
    if (canManageTenant(actor)) {
      const tabs: AppTab[] = ['exposure', 'findings', 'fix-intelligence', 'vuln-repo', 'campaigns', 'inventory', 'connect', 'admin', 'configurations'];
      if (aiSecurityEnabled) tabs.splice(2, 0, 'policies');
      return tabs;
    }
    const tabs: AppTab[] = ['exposure'];
    if (canRunSecurityWorkflow(actor) || canViewReadOnly(actor)) {
      tabs.push('findings', 'fix-intelligence', 'vuln-repo', 'campaigns', 'inventory');
      if (aiSecurityEnabled) tabs.push('policies');
    }
    if (canAccessPlatformConsole(actor)) {
      tabs.push('operations');
    }
    if (canManageInventorySources(actor)) {
      tabs.push('connect');
    }
    if (canManageTenant(actor) || canManageUsers(actor)) {
      tabs.push('admin');
    }
    if (canManageRiskPolicy(actor)) {
      tabs.push('configurations');
    }
    return tabs;
  }, [actor, aiSecurityEnabled, platformScopeOwner]);
  const inventoryAssetsQuery = useQuery({
    queryKey: ['inventory-nav-assets'],
    queryFn: api.listAssets,
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventorySoftwareQuery = useQuery({
    queryKey: ['inventory-nav-software-identities'],
    queryFn: () => api.listSoftwareIdentities({ page: 0, size: 1 }),
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventoryBomQuery = useQuery({
    queryKey: ['inventory-nav-bom-inventory'],
    queryFn: () => api.listBomInventory(0, 1),
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventoryPillCounts = React.useMemo(() => {
    const assets = inventoryAssetsQuery.data ?? [];
    return {
      hosts: assets.filter((asset) => asset.type.toUpperCase() === 'HOST').length,
      applications: assets.filter((asset) => asset.type.toUpperCase() === 'APPLICATION').length,
      containerImages: assets.filter((asset) => asset.type.toUpperCase() === 'CONTAINER_IMAGE').length,
      software: inventorySoftwareQuery.data?.totalElements ?? 0,
      bomInventory: inventoryBomQuery.data?.length ?? 0
    };
  }, [inventoryAssetsQuery.data, inventoryBomQuery.data?.length, inventorySoftwareQuery.data?.totalElements]);
  const visibleInventoryPills = React.useMemo(
    () => INVENTORY_PILL_ORDER.filter((item) => !item.countKey || inventoryPillCounts[item.countKey] > 0),
    [inventoryPillCounts]
  );

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  React.useEffect(() => {
    setNavOpen(false);
    setSettingsMenuOpen(false);
    setPersonaDialogOpen(false);
  }, [location.pathname]);

  React.useEffect(() => {
    if (personaDialogOpen && testPersonas.enabled && testPersonas.personas.length === 0 && !testPersonas.loading) {
      testPersonas.loadPersonas();
    }
  }, [personaDialogOpen, testPersonas]);

  const navigateToTab = (tab: AppTab): void => {
    navigate(pathForTab(tab));
  };

  const displayRole = actor?.roles?.[0]?.replace(/^ROLE_/, '').replace(/_/g, ' ') ?? 'No role';
  const tenantLabel = actor?.tenantName ?? (canAccessPlatformConsole(actor) ? 'Platform' : 'No tenant');
  const actorLabel = actor?.principal ?? actor?.userId ?? 'Unknown user';
  const activePersonaLabel = testPersonas.activePersona
    ? `Impersonating: ${testPersonas.activePersona.persona.label}`
    : null;

  const handleLogout = React.useCallback(() => {
    clearStoredAuthToken();
    queryClient.clear();
    navigate('/login', { replace: true });
  }, [navigate, queryClient]);

  const openPersonaDialog = (): void => {
    setSettingsMenuOpen(false);
    setPersonaDialogOpen(true);
  };

  const selectBackendPersona = (persona: TestPersona): void => {
    testPersonas.impersonateBackend(persona);
    setPersonaDialogOpen(false);
  };

  const selectPreviewPersona = (persona: TestPersona): void => {
    testPersonas.previewPersona(persona);
    setPersonaDialogOpen(false);
  };

  const resetPersona = (): void => {
    testPersonas.resetPersona();
    setPersonaDialogOpen(false);
  };

  const pageTitle = React.useMemo(() => {
    if (activeTab === 'exposure') return 'Exposure Dashboard';
    if (activeTab === 'admin') return 'Tenant Administration';
    if (activeTab === 'connect') return 'Connectors';
    if (activeTab === 'configurations') return 'Configurations';
    if (activeTab === 'platform') {
      const view = normalizePlatformRouteView(location.pathname.split('/')[2]);
      if (view === 'vuln-intel') return 'Vulnerability Intelligence';
      if (view === 'eol') return 'End-of-Life';
      if (view === 'operations') return 'Operations';
      return 'Tenant Management';
    }
    if (activeTab === 'platform-policies') return 'Policy Distribution';
    return titleForTab(activeTab);
  }, [activeTab, location.pathname]);

  const tenantScopedTabs = new Set<AppTab>(['exposure', 'findings', 'fix-intelligence', 'policies', 'inventory', 'admin', 'configurations']);
  if (actor && isPlatformScope && tenantScopedTabs.has(activeTab)) {
    return <Navigate to={pathForPlatformView('tenants')} replace state={{ platformMessage: 'Select a tenant to continue.' }} />;
  }
  if (actor && isPlatformScope && location.pathname.startsWith('/vuln-repo/campaigns')) {
    return <Navigate to={pathForPlatformView('tenants')} replace state={{ platformMessage: 'Select a tenant to continue.' }} />;
  }
  if (
    actor
    && platformScopeOwner
    && (location.pathname.startsWith('/vuln-repo/org-cves')
      || location.pathname.startsWith('/vuln-repo/software-assets')
      || location.pathname.startsWith('/vuln-repo/host-assets'))
  ) {
    return <Navigate to={pathForVulnRepoView('dashboard')} replace />;
  }

  const renderNavButton = (tab: AppTab): React.ReactNode => (
    <button
      key={tab}
      className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
      onClick={() => navigateToTab(tab)}
    >
      <span className="nav-label">{titleForTab(tab)}</span>
    </button>
  );

  const renderExpandableNavButton = (
    tab: AppTab,
    expanded: boolean,
    onToggleExpanded: () => void,
    subItems: Array<{ key: string; label: string }>,
    isSubItemActive: (key: string) => boolean,
    onSubItemClick: (key: string) => void
  ): React.ReactNode => (
    <React.Fragment key={tab}>
      <div
        className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
      >
        <button type="button" className="nav-label nav-destination" onClick={() => navigateToTab(tab)}>
          {titleForTab(tab)}
        </button>
        <button
          type="button"
          className="nav-expand-toggle"
          aria-expanded={expanded}
          aria-label={expanded ? `Collapse ${titleForTab(tab)} sections` : `Expand ${titleForTab(tab)} sections`}
          onClick={onToggleExpanded}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            {expanded ? <path d="M6 15l6-6 6 6" /> : <path d="M6 9l6 6 6-6" />}
          </svg>
        </button>
      </div>
      {expanded && (
        <div className="nav-sub-list">
          {subItems.map((item) => (
            <button
              key={item.key}
              type="button"
              className={isSubItemActive(item.key) ? 'nav-sub-btn active' : 'nav-sub-btn'}
              onClick={() => onSubItemClick(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </React.Fragment>
  );

  return (
    <>
      <LegacyQueryRedirect />
      <div className="app-shell">
        <aside className={navOpen ? 'sidebar open' : 'sidebar'}>
          <div className="brand-block compact">
            <div className="brand-mark">S</div>
            <div className="brand">Scout</div>
          </div>

          <div className="nav-main-section">
            {visiblePrimaryNavTabs
              .filter((tab) => tab !== 'policies' && tab !== 'connect' && tab !== 'admin' && tab !== 'configurations')
              .map((tab) => {
              if (tab === 'findings' && aiSecurityEnabled) {
                return renderExpandableNavButton(
                  tab,
                  findingsNavExpanded,
                  () => setFindingsNavExpanded((current) => !current),
                  [
                    { key: 'vulnerability', label: 'Vulnerability Findings' },
                    { key: 'ai', label: 'AI Findings' },
                  ],
                  (key) => key === 'ai' ? location.pathname.startsWith('/findings/ai') : location.pathname === '/findings',
                  (key) => navigate(key === 'ai' ? pathForAiFindings() : '/findings')
                );
              }
              if (tab === 'fix-intelligence') {
                return renderExpandableNavButton(
                  tab,
                  fixNavExpanded,
                  () => setFixNavExpanded((current) => !current),
                  FIX_VIEWS,
                  (key) => activeTab === 'fix-intelligence' && pathSegments[1] === key,
                  (key) => navigate(pathForFixIntelligenceView(key as FixIntelligenceRouteView))
                );
              }
              if (tab === 'inventory') {
                return renderExpandableNavButton(
                  tab,
                  inventoryNavExpanded,
                  () => setInventoryNavExpanded((current) => !current),
                  visibleInventoryPills,
                  (key) => activeTab === 'inventory' && activeInventoryView === key,
                  (key) => navigate(pathForInventoryView(key as InventoryViewKey))
                );
              }
              return renderNavButton(tab);
            })}
            {visiblePrimaryNavTabs.includes('policies') && renderNavButton('policies')}

            {aiSecurityEnabled && renderExpandableNavButton(
              'ai',
              aiInventoryNavExpanded,
              () => setAiInventoryNavExpanded((current) => !current),
              AI_INVENTORY_NAV_ITEMS,
              (key) => {
                const params = new URLSearchParams(location.search);
                if (key === 'overview') return location.pathname === '/inventory/ai' || location.pathname === '/inventory/ai/overview';
                if (key === 'mcp-servers') return location.pathname === '/inventory/ai/mcp' && params.get('artifactRole') === 'MCP_SERVER';
                if (key === 'data-stores') return location.pathname === '/inventory/ai/knowledge-data' && params.get('artifactRole') === 'DATA_STORE';
                if (key === 'AGENTS') return location.pathname === '/inventory/ai/agents';
                if (key === 'others') return location.pathname === '/inventory/ai/assets' && params.get('view') === 'others';
                const item = AI_INVENTORY_NAV_ITEMS.find((candidate) => candidate.key === key);
                return location.pathname === '/inventory/ai/assets' && params.get('nativeKind') === item?.nativeKind;
              },
              (key) => {
                if (key === 'overview') return navigate(pathForAiInventoryOverview());
                if (key === 'mcp-servers') return navigate('/inventory/ai/mcp?artifactRole=MCP_SERVER');
                if (key === 'data-stores') return navigate('/inventory/ai/knowledge-data?artifactRole=DATA_STORE');
                if (key === 'AGENTS') return navigate(pathForInventoryAiAgents());
                if (key === 'others') return navigate('/inventory/ai/assets?view=others');
                const item = AI_INVENTORY_NAV_ITEMS.find((candidate) => candidate.key === key);
                return navigate(`/inventory/ai/assets?nativeKind=${encodeURIComponent(item?.nativeKind ?? '')}`);
              }
            )}

          </div>

          {platformScopeOwner && (
            <div className="nav-ops-section">
              <button
                className={location.pathname.startsWith('/platform/operations') ? 'nav-btn active' : 'nav-btn'}
                onClick={() => navigate(pathForPlatformView('operations'))}
              >
                <span className="nav-label">Operations</span>
              </button>
            </div>
          )}

          <div className="nav-bottom-section">
            {BOTTOM_NAV_TABS.map((tab) => renderNavButton(tab))}
            {visiblePrimaryNavTabs.includes('connect') && renderNavButton('connect')}
            {visiblePrimaryNavTabs.includes('configurations') && renderExpandableNavButton(
              'configurations',
              configurationsNavExpanded,
              () => setConfigurationsNavExpanded((current) => !current),
              CONFIGURATIONS_PILL_ORDER,
              (key) => activeTab === 'configurations' && activeConfigurationsView === key,
              (key) => navigate(pathForConfigurationsView(key as ConfigurationsRouteView))
            )}
            {visiblePrimaryNavTabs.includes('admin') && renderExpandableNavButton(
              'admin',
              adminNavExpanded,
              () => setAdminNavExpanded((current) => !current),
              ADMIN_PILL_ORDER,
              (key) => activeTab === 'admin' && activeAdminView === key,
              (key) => navigate(pathForAdminView(key as AdminRouteView))
            )}
          </div>
        </aside>

        <main className="content">
          <header className="topbar">
            <div className="topbar-copy">
              <div className="eyebrow">Enterprise Vulnerability Operations</div>
              <h1>{pageTitle}</h1>
            </div>
            <div className="topbar-actions">
              <button type="button" className="tenant-context-pill" title={`${actorLabel} · ${displayRole}`}
                aria-label={`${tenantLabel} ${displayRole}: Open account menu`} aria-expanded={settingsMenuOpen}
                onClick={() => setSettingsMenuOpen((open) => !open)}>
                <span>{tenantLabel}{' '}</span>
                <small>{displayRole}</small>
              </button>
              {activePersonaLabel && (
                <div className={`tenant-context-pill test-persona-pill ${testPersonas.activePersona?.mode === 'preview' ? 'preview' : ''}`}>
                  <span>{activePersonaLabel}</span>
                  <small>{testPersonas.activePersona?.mode === 'preview' ? 'UI preview only' : 'Backend-backed'}</small>
                </div>
              )}
              {testPersonas.activePersona?.mode === 'preview' && (
                <div className="test-persona-inline-warning" role="status">
                  UI preview only - backend authorization still uses the current real session.
                </div>
              )}
              <button
                className="btn btn-secondary nav-toggle"
                onClick={() => setNavOpen((current) => !current)}
              >
                {navOpen ? 'Close Menu' : 'Menu'}
              </button>
              <div className="settings-menu-wrap">
                <button
                  className={settingsMenuOpen || ['admin', 'platform'].includes(activeTab) ? 'btn btn-secondary theme-icon-btn active' : 'btn btn-secondary theme-icon-btn'}
                  onClick={() => setSettingsMenuOpen((open) => !open)}
                  aria-label="Open settings menu"
                  aria-expanded={settingsMenuOpen}
                  title="Settings"
                >
                  <SettingsIcon />
                </button>
                {settingsMenuOpen && (
                  <div className="settings-menu" role="menu">
                    <div className="settings-menu-header">
                      <div className="brand-mark settings-menu-mark">S</div>
                      <strong>Settings</strong>
                      <span>{actorLabel}</span>
                    </div>
                    {testPersonas.enabled && (
                      <button
                        type="button"
                        className="settings-menu-item"
                        role="menuitem"
                        onClick={openPersonaDialog}
                      >
                        <span>Impersonate User</span>
                        <small>Open non-production test personas</small>
                      </button>
                    )}
                    {actor?.roles.includes('PLATFORM_OWNER') && (
                      <button
                        type="button"
                        className="settings-menu-item"
                        role="menuitem"
                        onClick={() => {
                          setSettingsMenuOpen(false);
                          navigate('/authorized-workspaces');
                        }}
                      >
                        <span>Authorized Workspaces</span>
                        <small>Open only tenant-approved access</small>
                      </button>
                    )}
                    <button
                      type="button"
                      className="settings-menu-item settings-menu-item-logout"
                      role="menuitem"
                      onClick={handleLogout}
                    >
                      <span>Log out</span>
                    </button>
                  </div>
                )}
              </div>
              <button
                className="btn btn-secondary theme-icon-btn"
                onClick={() => setTheme((current) => (current === 'dark' ? 'light' : 'dark'))}
                aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
              >
                {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
              </button>
            </div>
          </header>

          {activeTab === 'vuln-repo' && (
            <div className="section-tab-row">
              {VULN_REPO_NAV_ITEMS.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={activeVulnRepoView === item.key ? 'section-tab-btn active' : 'section-tab-btn'}
                  onClick={() => navigate(pathForVulnRepoView(item.key))}
                >
                  {item.label}
                </button>
              ))}
            </div>
          )}

          <RouteErrorBoundary resetKey={location.pathname}>
          <React.Suspense fallback={routeLoadingFallback()}>
            <Routes>
              <Route path="/exposure" element={<ExposureDashboardRoute />} />
              <Route path="/" element={<HomeRoute />} />
              <Route path="/findings/:displayId" element={<FindingDetailRoute />} />
              <Route path="/findings/ai/exposures" element={<AiSecurityRoute><AiExposuresPage /></AiSecurityRoute>} />
              <Route path="/findings/ai/exposures/:exposureId" element={<AiSecurityRoute><AiExposuresPage /></AiSecurityRoute>} />
              <Route path="/findings/ai/vulnerabilities" element={<AiSecurityRoute><AiFindingsPage /></AiSecurityRoute>} />
              <Route path="/findings/ai/:findingId" element={<AiFindingDetailRoute />} />
              <Route path="/findings/ai" element={<AiSecurityRoute><AiFindingsPage /></AiSecurityRoute>} />
              <Route path="/findings" element={<FindingsRoute />} />
              <Route path="/fix-intelligence/details/:fixId" element={<FixDetailPage />} />
              <Route path="/fix-intelligence/:view?" element={<FixIntelligenceRoute />} />
              <Route path="/policies" element={<AiSecurityRoute><AiPoliciesPage /></AiSecurityRoute>} />
              <Route path="/policies/:policyId" element={<AiSecurityRoute><AiPolicyDetailRoute /></AiSecurityRoute>} />
              <Route path="/platform/ai-policies/:policyId" element={<PlatformAiPolicyDetailRoute />} />
              <Route path="/operations/:operationsView?" element={<OperationsRoute />} />
              <Route path="/vulnerability-intelligence" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/vulnerabilities" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/org-cves/:cveId?" element={<LegacyVulnerabilityIntelWorkbenchRoute />} />
              <Route path="/vuln-repo" element={<VulnRepoDashboardRoute />} />
              <Route path="/vuln-repo/policies" element={<Navigate to="/platform/ai-policies" replace />} />
              <Route path="/vuln-repo/intel/:externalId" element={<PlatformVulnIntelDetailPage />} />
              <Route path="/vuln-repo/vulnerabilities" element={<VulnRepoVulnerabilitiesPage />} />
              <Route path="/vuln-repo/campaigns" element={<CampaignsPage />} />
              <Route path="/vuln-repo/campaigns/:id" element={<CampaignDetailPage />} />
              <Route path="/vuln-repo/software-assets" element={<VulnRepoSoftwareAssetsPage />} />
              <Route path="/vuln-repo/host-assets/:assetId" element={<VulnRepoHostAssetRoute />} />
              <Route path="/vuln-repo/org-cves/:cveId/assets" element={<VulnRepoCveAssetsPage />} />
              <Route path="/vuln-repo/org-cves/:cveId/software" element={<VulnRepoCveSoftwarePage />} />
              <Route path="/vuln-repo/org-cves/:cveId?" element={<VulnRepoWorkbenchRoute />} />
              <Route path="/inventory/hosts/:assetId" element={<InventoryHostAssetRoute />} />
              <Route path="/inventory/ai/overview" element={<AiSecurityRoute><AiInventoryPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/agent-versions" element={<AiSecurityRoute><AiInventoryAssetsPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/agents" element={<AiSecurityRoute><AiInventoryAssetsPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/assets" element={<AiSecurityRoute><AiInventoryAssetsPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/knowledge-data" element={<AiSecurityRoute><AiKnowledgeMcpInventoryPage kind="knowledge-data" /></AiSecurityRoute>} />
              <Route path="/inventory/ai/mcp" element={<AiSecurityRoute><AiKnowledgeMcpInventoryPage kind="mcp" /></AiSecurityRoute>} />
              <Route path="/inventory/ai/executions" element={<Navigate to="/inventory/ai" replace />} />
              <Route path="/inventory/ai/declared-resources" element={<AiSecurityRoute><AiBomDeclaredResourcesPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/declared-resources/:resourceId" element={<AiBomDeclaredResourceDetailRoute />} />
              <Route path="/connect/copilot-studio" element={<AiSecurityRoute><CopilotStudioConnectorPage /></AiSecurityRoute>} />
              <Route path="/inventory/ai/:assetId" element={<InventoryAiAssetRoute />} />
              <Route path="/inventory/software-identities/:softwareIdentityId" element={<SoftwareIdentityDetailRoute />} />
              <Route path="/inventory/:inventoryView?" element={<InventoryRoute />} />
              <Route path="/end-of-life" element={<EndOfLifeRoute />} />
              <Route path="/connect/:connectView?" element={<ConnectRoute />} />
              <Route path="/admin/:adminView?" element={<AdminRoute />} />
              <Route path="/platform/:platformView?" element={<PlatformRoute />} />
              <Route path="/authorized-workspaces" element={<AuthorizedWorkspacesRoute />} />
              <Route path="/configurations/:configView?" element={<ConfigurationsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </React.Suspense>
          </RouteErrorBoundary>
        </main>

        {navOpen && <button type="button" className="mobile-nav-backdrop" onClick={() => setNavOpen(false)} aria-label="Close navigation" />}
      </div>
      {personaDialogOpen && (
        <div className="modal-backdrop" role="presentation" onClick={() => setPersonaDialogOpen(false)}>
          <section
            className="test-persona-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="test-persona-dialog-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="test-persona-dialog-header">
              <div>
                <h2 id="test-persona-dialog-title">Non-production test personas</h2>
                <p>Choose a persona for backend-backed authorization, or preview role-gated UI only.</p>
              </div>
              <button
                type="button"
                className="btn btn-secondary theme-icon-btn"
                onClick={() => setPersonaDialogOpen(false)}
                aria-label="Close persona dialog"
                title="Close"
              >
                X
              </button>
            </div>
            {testPersonas.loading && testPersonas.personas.length === 0 && (
              <div className="test-persona-empty">Loading personas...</div>
            )}
            {testPersonas.error && (
              <div className="test-persona-warning" role="alert">{testPersonas.error}</div>
            )}
            <div className="test-persona-list">
              {testPersonas.personas.map((persona) => (
                <div className="test-persona-row" key={persona.key}>
                  <div>
                    <strong>{persona.label}</strong>
                    <small>{persona.tenantName ?? 'Platform'} · {persona.roles.map((role) => role.replace(/^ROLE_/, '').replace(/_/g, ' ')).join(', ')}</small>
                  </div>
                  <div className="test-persona-actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => selectBackendPersona(persona)}
                      disabled={testPersonas.loading}
                    >
                      Use
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => selectPreviewPersona(persona)}
                      disabled={testPersonas.loading}
                    >
                      Preview
                    </button>
                  </div>
                </div>
              ))}
            </div>
            {testPersonas.activePersona?.mode === 'preview' && (
              <div className="test-persona-warning">
                UI preview only - backend authorization still uses the current real session.
              </div>
            )}
            {testPersonas.activePersona && (
              <div className="test-persona-dialog-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={resetPersona}
                >
                  Reset to real user
                </button>
              </div>
            )}
          </section>
        </div>
      )}
    </>
  );
}

export default function App() {
  return (
    <React.Suspense fallback={routeLoadingFallback()}>
      <PerformanceInstrumentation />
      <Routes>
        <Route path="/demo" element={<DemoLandingPage />} />
        <Route path="/demo/blog" element={<BlogIndexPage />} />
        <Route path="/demo/blog/zero-day-response-hours-not-weeks" element={<ZeroDayBlogPage />} />
        <Route path="/demo/blog/mythos-readiness" element={<MythosReadinessBlogPage />} />
        <Route path="/demo/blog/why-your-sbom-tool-doesnt-know-whats-exploitable" element={<SbomExploitabilityBlogPage />} />
        <Route path="/demo/request" element={<DemoRequestPage />} />
        <Route path="/demo/request/success" element={<DemoRequestSuccessPage />} />
        <Route path="/demo/expired" element={<DemoExpiredPage />} />
        <Route path="/invite" element={<DemoInvitePage />} />
        <Route path="/tenant-invite" element={<TenantInvitePage />} />
        <Route path="/setup" element={<SetupSessionPage />} />
        <Route path="/invite/:token" element={<DemoInvitePage />} />
        <Route path="/tenant-invite/:token" element={<TenantInvitePage />} />
        <Route path="/setup/:token" element={<SetupSessionPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/*" element={
          <AuthSessionBoundary>
            <AppShell />
          </AuthSessionBoundary>
        } />
      </Routes>
    </React.Suspense>
  );
}
