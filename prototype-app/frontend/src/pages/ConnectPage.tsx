import React from 'react';
import { Navigate, useSearchParams } from 'react-router-dom';
import { IngestionPage } from './IngestionPage';
import { SourcesPage } from './SourcesPage';
import { AssetsPage } from './AssetsPage';
import { InventoryRunQueuePage } from './InventoryRunQueuePage';
import { EolSourcePanel } from '../components/EolSourcePanel';
import { SccmConnectorPage } from './SccmConnectorPage';
import { AwsDiscoveryConnectorPage } from './AwsDiscoveryConnectorPage';
import { AzureDiscoveryConnectorPage } from './AzureDiscoveryConnectorPage';
import { api } from '../api/client';
import type { VulnIntelSourceStatus, VulnIntelSourcesSummary } from '../api/client';
import {
  useAwsDiscoveryConfigQuery,
  useAzureDiscoveryConfigQuery,
  useSccmCmdbConfigQuery,
  useServiceNowCmdbConfigQuery
} from '../features/connect/queries';
import { useActor } from '../features/auth/context';
import { canManageSourceFilters, hasRole } from '../features/auth/roles';
import { VulnerabilitySourcesSection } from './ConfigurationsPage';
import { timeAgo } from '../lib/time';
import { BomManagementPage } from './BomManagementPage';
import { AiSecurityConnectorPage } from './AiSecurityConnectorPage';
import { AiSecurityAzureConnectorPage } from './AiSecurityAzureConnectorPage';
import { CopilotStudioConnectorPage } from './CopilotStudioConnectorPage';
import { pathForPlatformView } from '../app/routes';
import { canUseEntitlement } from '../features/auth/entitlements';

type ConnectorId =
  | 'sbom-endpoint'
  | 'sbom-github'
  | 'bom-management'
  | 'servicenow-cmdb'
  | 'sccm-cmdb'
  | 'aws-discovery'
  | 'azure-discovery'
  | 'ai-security-aws'
  | 'ai-security-azure'
  | 'ai-security-copilot'
  | 'nvd-api'
  | 'cisa-kev'
  | 'ghsa-feed'
  | 'microsoft-csaf-vex'
  | 'redhat-csaf-vex'
  | 'advisory-feed'
  | 'endoflife-date'
  | 'euvd-feed'
  | 'jvn-feed';

type ConnectView = 'sources' | 'run-history';

const CONNECT_VIEW_ORDER: ConnectView[] = ['sources', 'run-history'];

type ConnectorDefinition = {
  id: ConnectorId;
  name: string;
  summary: string;
  icon: React.ReactNode;
};

type InventoryConnectorStatus = {
  hasSynced: boolean;
  isFailed: boolean;
  demoDisabled: boolean;
  lastSyncAt?: string;
};

/* ── Inline SVG connector icons ─────────────────────────────────────────────
   Cross-platform consistent icons replacing OS-dependent emoji.
   Each icon is 20×20, stroke-based, using currentColor for theme support. */

const IconGlobe = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <ellipse cx="10" cy="10" rx="4" ry="8" />
    <path d="M2.5 10h15" />
    <path d="M3.5 5.5h13" />
    <path d="M3.5 14.5h13" />
  </svg>
);

const IconGitHub = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
    <path d="M10 1.5a8.5 8.5 0 0 0-2.69 16.56c.43.08.58-.18.58-.4v-1.51c-2.37.52-2.87-1.01-2.87-1.01a2.26 2.26 0 0 0-.95-1.25c-.77-.53.06-.52.06-.52a1.8 1.8 0 0 1 1.31.88 1.82 1.82 0 0 0 2.49.71 1.82 1.82 0 0 1 .54-1.14c-1.89-.22-3.88-.95-3.88-4.22a3.3 3.3 0 0 1 .88-2.29 3.07 3.07 0 0 1 .08-2.26s.72-.23 2.35.88a8.1 8.1 0 0 1 4.28 0c1.63-1.1 2.35-.88 2.35-.88a3.07 3.07 0 0 1 .08 2.26 3.3 3.3 0 0 1 .88 2.29c0 3.28-2 4-3.9 4.21a2.04 2.04 0 0 1 .58 1.58v2.35c0 .22.15.49.59.4A8.5 8.5 0 0 0 10 1.5Z" />
  </svg>
);

const IconMicrosoft = (
  <svg width="40" height="40" viewBox="0 0 40 40" aria-hidden="true">
    <rect x="3" y="3" width="15.6" height="15.6" fill="#F25022" />
    <rect x="21.4" y="3" width="15.6" height="15.6" fill="#7FBA00" />
    <rect x="3" y="21.4" width="15.6" height="15.6" fill="#00A4EF" />
    <rect x="21.4" y="21.4" width="15.6" height="15.6" fill="#FFB900" />
  </svg>
);

const IconAws = (
  <svg width="56" height="40" viewBox="0 0 56 40" aria-hidden="true">
    <text x="28" y="27" textAnchor="middle" fontSize="21" fontWeight="700"
          fontFamily="Helvetica, Arial, sans-serif" fill="#FF9900">aws</text>
  </svg>
);

const IconAzure = (
  <svg width="44" height="40" viewBox="0 0 44 40" aria-hidden="true">
    <path d="M17.2 5.2h10.4L16.6 26.2H8z" fill="#0078D4" />
    <path d="M19.2 28.4 28.8 10.8l8.6 23.8H14.2z" fill="#50BCEB" />
  </svg>
);

const IconServiceNowBrand = (
  <svg width="40" height="40" viewBox="0 0 40 40" aria-hidden="true">
    <rect x="2" y="2" width="36" height="36" rx="7" fill="#12263A" />
    <text x="20" y="25.5" textAnchor="middle" fontSize="12.6" fontWeight="700"
          fontFamily="Helvetica, Arial, sans-serif" fill="#ffffff">NOW</text>
  </svg>
);

const IconShield = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 2 4 5v4.5c0 4.14 2.56 7.02 6 8.5 3.44-1.48 6-4.36 6-8.5V5l-6-3Z" />
    <path d="M7.5 10l2 2 3.5-4" />
  </svg>
);

const IconWarning = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 3 2 17h16L10 3Z" />
    <path d="M10 8v4" />
    <circle cx="10" cy="14.5" r="0.5" fill="currentColor" stroke="none" />
  </svg>
);

const IconWindow = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="14" height="14" rx="2" />
    <path d="M3 7h14" />
    <path d="M10 7v10" />
  </svg>
);

const IconHat = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 14c0-2 3.13-5 7-5s7 3 7 5" />
    <ellipse cx="10" cy="14" rx="8" ry="2.5" />
    <path d="M6 9.5C6 7.5 7.8 5 10 5s4 2.5 4 4.5" />
  </svg>
);

const IconBrain = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 17V8" />
    <path d="M7 4a3 3 0 0 0-3 3c0 1.1.6 2 1.5 2.5a3 3 0 0 0 1 5.5" />
    <path d="M13 4a3 3 0 0 1 3 3c0 1.1-.6 2-1.5 2.5a3 3 0 0 1-1 5.5" />
    <path d="M7 4c0-1.1.9-2 2-2h2c1.1 0 2 .9 2 2" />
  </svg>
);

const IconCalendar = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="4" width="14" height="13" rx="2" />
    <path d="M3 8h14" />
    <path d="M7 2v4" />
    <path d="M13 2v4" />
  </svg>
);

const IconEu = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <path d="M6 8h5" />
    <path d="M6 10h4" />
    <path d="M6 12h5" />
    <path d="M13 8v4" />
  </svg>
);

const IconJvn = (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="10" cy="10" r="8" />
    <path d="M10 6v5" />
    <path d="M7 8.5l3-2.5 3 2.5" />
    <path d="M7.5 13.5c0 1 1.1 1.5 2.5 1.5s2.5-.5 2.5-1.5v-4" />
  </svg>
);

const CONNECT_SOURCE_QUERY_KEY = 'connectSource';
const CONNECTORS: ConnectorDefinition[] = [
  {
    id: 'sbom-endpoint',
    name: 'SBOM API Endpoint',
    summary: 'Fetch SBOM JSON from authenticated API endpoints.',
    icon: IconGlobe
  },
  {
    id: 'sbom-github',
    name: 'GitHub',
    summary: 'SBOM ingestion from GitHub repositories and GHCR container images.',
    icon: IconGitHub
  },
  {
    id: 'bom-management',
    name: 'BOM Management',
    summary: 'Ingest SBOM, AI BOM, CBOM, and Vendor BOM via URL or file upload.',
    icon: (
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 3h8l4 4v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" />
        <path d="M12 3v4h4" />
        <path d="M7 9h6" />
        <path d="M7 12h6" />
        <path d="M7 15h4" />
      </svg>
    )
  },
  {
    id: 'servicenow-cmdb',
    name: 'ServiceNow',
    summary: 'Host inventory from ServiceNow CI records via Table APIs.',
    icon: IconServiceNowBrand
  },
  {
    id: 'sccm-cmdb',
    name: 'SCCM/MECM',
    summary: 'Hardware asset and software inventory from Microsoft Configuration Manager.',
    icon: IconMicrosoft
  },
  {
    id: 'aws-discovery',
    name: 'AWS',
    summary: 'Cloud infrastructure discovery from AWS EC2 and systems inventory.',
    icon: IconAws
  },
  {
    id: 'azure-discovery',
    name: 'Azure',
    summary: 'Disabled for the pilot. Existing Azure cloud inventory is retained.',
    icon: IconAzure
  },
  {
    id: 'ai-security-aws',
    name: 'AWS Bedrock',
    summary: 'AI resource discovery and posture assessment for AWS Bedrock agents and models.',
    icon: IconAws
  },
  {
    id: 'ai-security-azure',
    name: 'Azure AI',
    summary: 'AI resource discovery and posture assessment for Azure Foundry and AI services.',
    icon: IconAzure
  },
  {
    id: 'ai-security-copilot',
    name: 'Copilot Studio',
    summary: 'Discovery of Microsoft Copilot agents and AI components via Dataverse.',
    icon: IconMicrosoft
  },
  {
    id: 'nvd-api',
    name: 'NVD Vulnerability Feed',
    summary: '',
    icon: IconShield
  },
  {
    id: 'cisa-kev',
    name: 'CISA KEV Feed',
    summary: 'Ingest known-exploited vulnerabilities and update prioritization.',
    icon: IconWarning
  },
  {
    id: 'ghsa-feed',
    name: 'GitHub Advisory Database (GHSA)',
    summary: 'Ingest GHSA advisories with package-version applicability for correlation.',
    icon: IconGitHub
  },
  {
    id: 'microsoft-csaf-vex',
    name: 'Microsoft CSAF + VEX',
    summary: 'Ingest Microsoft CSAF advisories and VEX applicability data.',
    icon: IconWindow
  },
  {
    id: 'redhat-csaf-vex',
    name: 'Red Hat CSAF + VEX',
    summary: 'Ingest Red Hat CSAF advisories and VEX applicability data.',
    icon: IconHat
  },
  {
    id: 'advisory-feed',
    name: 'Advisory Imports',
    summary: 'Import curated advisories for package and product mappings.',
    icon: IconBrain
  },
  {
    id: 'endoflife-date',
    name: 'endoflife.date EOL Feed',
    summary: 'Run endoflife.date catalog, release, mapping, and denormalization jobs.',
    icon: IconCalendar
  },
  {
    id: 'euvd-feed',
    name: 'ENISA EUVD Feed',
    summary: 'Ingest ENISA European Vulnerability Database records and sync EUVD-to-CVE correlations.',
    icon: IconEu
  },
  {
    id: 'jvn-feed',
    name: 'JVN Vulnerability Database',
    summary: 'Ingest Japan Vulnerability Notes (JVNdb) records via the MyJVN API and sync JVNDB-to-CVE correlations.',
    icon: IconJvn
  }
];

const VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS: ConnectorId[] = [
  'nvd-api',
  'cisa-kev',
  'ghsa-feed',
  'microsoft-csaf-vex',
  'redhat-csaf-vex',
  'advisory-feed'
];

// Order is the display order within each section.
const INVENTORY_CONNECTOR_IDS: ConnectorId[] = [
  'sbom-github',
  'servicenow-cmdb',
  'sccm-cmdb',
  'aws-discovery',
  'azure-discovery',
  'ai-security-aws',
  'ai-security-azure',
  'ai-security-copilot'
];

const BOM_CONNECTOR_IDS: ConnectorId[] = ['sbom-endpoint', 'bom-management'];

// The AI connectors are entitlement-gated, so they drop out of Inventory rather than
// leaving an empty section behind.
const AI_CONNECTOR_IDS: ConnectorId[] = ['ai-security-aws', 'ai-security-azure', 'ai-security-copilot'];

function formatInstantConnect(iso?: string): string {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleString();
}

function EuvdConnectorPanel() {
  const actor = useActor();
  const canSync = hasRole(actor, 'PLATFORM_OWNER');
  const [status, setStatus] = React.useState<VulnIntelSourceStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');

  const loadStatus = React.useCallback(async () => {
    try {
      const summary: VulnIntelSourcesSummary = await api.getVulnIntelSourcesSummary();
      setStatus(summary?.sources?.EUVD ?? summary?.sources?.euvd ?? null);
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void loadStatus(); }, [loadStatus]);

  const executeSync = async () => {
    if (!canSync) { setMessage('Platform owner access is required to execute EUVD sync.'); return; }
    setBusy(true);
    setMessage('');
    try {
      const response = await api.syncEuvd();
      setMessage((response as { message?: string }).message || 'EUVD sync queued.');
      await loadStatus();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'EUVD sync failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>ENISA EUVD Feed</h3>
        <span className="panel-caption">
          Ingest the latest EUVD records from ENISA and refresh EUVD-to-CVE cross-source correlations.
        </span>
      </div>
      <div style={{ padding: '16px 24px', display: 'grid', gap: 16 }}>
        {message && (
          <div className="notice">{message}</div>
        )}
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-muted)', padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: '1rem' }}>EUVD Vulnerability Feed</div>
              <div className="field-hint" style={{ marginTop: 4 }}>
                Source records are stored separately and linked back to CVEs when cross-references exist.
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void executeSync()} disabled={!canSync || busy}>
              {busy ? 'Executing…' : 'Execute now'}
            </button>
          </div>
          <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Status</div>
              <div style={{ fontWeight: 700, marginTop: 4, textTransform: 'capitalize' }}>
                {loading ? 'Loading…' : (status?.status ?? 'never')}
              </div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Last completed</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>{formatInstantConnect(status?.completedAt)}</div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Fetched / Inserted / Updated</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>
                {(status?.recordsFetched ?? 0).toLocaleString()} / {(status?.recordsInserted ?? 0).toLocaleString()} / {(status?.recordsUpdated ?? 0).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="field-hint" style={{ marginTop: 12 }}>
            The execute action runs the backend EUVD sync endpoint immediately.
          </div>
        </div>
      </div>
    </section>
  );
}

function JvnConnectorPanel() {
  const actor = useActor();
  const canSync = hasRole(actor, 'PLATFORM_OWNER');
  const [status, setStatus] = React.useState<VulnIntelSourceStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');

  const loadStatus = React.useCallback(async () => {
    try {
      const summary: VulnIntelSourcesSummary = await api.getVulnIntelSourcesSummary();
      setStatus(summary?.sources?.['japan-vulndb'] ?? summary?.sources?.JVN ?? null);
    } catch {
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void loadStatus(); }, [loadStatus]);

  const executeSync = async () => {
    if (!canSync) { setMessage('Platform owner access is required to execute JVN sync.'); return; }
    setBusy(true);
    setMessage('');
    try {
      const response = await api.syncJvn();
      setMessage((response as { message?: string }).message || 'JVN sync queued.');
      await loadStatus();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'JVN sync failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>JVN Vulnerability Database</h3>
        <span className="panel-caption">
          Ingest Japan Vulnerability Notes (JVNdb) records via the MyJVN API and sync JVNDB-to-CVE cross-source correlations.
        </span>
      </div>
      <div style={{ padding: '16px 24px', display: 'grid', gap: 16 }}>
        {message && (
          <div className="notice">{message}</div>
        )}
        <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-muted)', padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: '1rem' }}>JVN Vulnerability Feed</div>
              <div className="field-hint" style={{ marginTop: 4 }}>
                Source records are stored separately and linked back to CVEs when cross-references exist.
              </div>
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void executeSync()} disabled={!canSync || busy}>
              {busy ? 'Executing…' : 'Execute now'}
            </button>
          </div>
          <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Status</div>
              <div style={{ fontWeight: 700, marginTop: 4, textTransform: 'capitalize' }}>
                {loading ? 'Loading…' : (status?.status ?? 'never')}
              </div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Last completed</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>{formatInstantConnect(status?.completedAt)}</div>
            </div>
            <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)', padding: 12 }}>
              <div className="field-hint">Fetched / Inserted / Updated</div>
              <div style={{ fontWeight: 700, marginTop: 4 }}>
                {(status?.recordsFetched ?? 0).toLocaleString()} / {(status?.recordsInserted ?? 0).toLocaleString()} / {(status?.recordsUpdated ?? 0).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="field-hint" style={{ marginTop: 12 }}>
            The execute action runs the backend JVN sync endpoint immediately. Records are fetched from the
            MyJVN API at jvndb.jvn.jp and correlated with CVEs where cross-references are present.
          </div>
        </div>
      </div>
    </section>
  );
}

function isConnectorId(value: string | null): value is ConnectorId {
  return CONNECTORS.some((connector) => connector.id === value);
}

function readConnectorFromSearch(searchParams: URLSearchParams): ConnectorId | null {
  const source = searchParams.get(CONNECT_SOURCE_QUERY_KEY);
  if (isConnectorId(source)) {
    return source;
  }
  return null;
}

function buildInventoryConnectorStatus(config: {
  configured?: boolean;
  lastSyncAt?: string;
  lastTestStatus?: string;
} | null, demoDisabled: boolean): InventoryConnectorStatus {
  const lastTestStatus = config?.lastTestStatus?.trim().toUpperCase();
  return {
    hasSynced: config?.lastSyncAt != null,
    isFailed: lastTestStatus === 'FAILED',
    demoDisabled,
    lastSyncAt: config?.lastSyncAt,
  };
}

type ConnectorDetailsProps = {
  connectorId: ConnectorId;
};

function ConnectorDetailContent({ connectorId }: ConnectorDetailsProps) {
  if (connectorId === 'sbom-endpoint') {
    return (
      <IngestionPage
        initialMode="endpoint"
        hideModeToggle
        title="SBOM API Endpoint Connector"
        caption="Configure endpoint URL/auth headers to fetch SBOM JSON."
      />
    );
  }
  if (connectorId === 'sbom-github') {
    return (
      <BomManagementPage
        title="GitHub BOM Connector"
        caption="Use GitHub repositories and GHCR attestations as BOM acquisition adapters inside the shared BOM management workflow."
        includeGithubSources
      />
    );
  }
  if (connectorId === 'bom-management') {
    return (
      <BomManagementPage
        title="BOM Management"
        caption="Ingest SBOM, AI BOM, CBOM, and Vendor BOM files via URL fetch or file upload."
        includeGithubSources
      />
    );
  }
  if (connectorId === 'nvd-api') {
    return (
      <SourcesPage
        focusSource="nvd"
        title="NVD Vulnerability Feed"
        caption="Configure NVD input filters and run NVD delta or full corpus syncs."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'cisa-kev') {
    return (
      <SourcesPage
        focusSource="kev"
        title="CISA KEV Feed"
        caption="Configure KEV input filters and run the known-exploited vulnerability feed."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'ghsa-feed') {
    return (
      <SourcesPage
        focusSource="ghsa"
        title="GitHub Advisory Database (GHSA)"
        caption="Configure GHSA severity filters and run package advisory ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'microsoft-csaf-vex') {
    return (
      <SourcesPage
        focusSource="microsoft-csaf"
        title="Microsoft CSAF + VEX"
        caption="Run Microsoft CSAF advisories and VEX applicability ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'redhat-csaf-vex') {
    return (
      <SourcesPage
        focusSource="redhat-csaf"
        title="Red Hat CSAF + VEX"
        caption="Configure Red Hat input filters and run CSAF/VEX ingestion."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'advisory-feed') {
    return (
      <SourcesPage
        focusSource="advisories"
        title="Advisory Imports"
        caption="Import curated advisories and seed demo advisory data."
        showQueue={false}
      />
    );
  }
  if (connectorId === 'endoflife-date') {
    return (
      <EolSourcePanel
        title="endoflife.date EOL Feed"
        caption=""
      />
    );
  }
  if (connectorId === 'euvd-feed') {
    return <EuvdConnectorPanel />;
  }
  if (connectorId === 'jvn-feed') {
    return <JvnConnectorPanel />;
  }
  if (connectorId === 'servicenow-cmdb') {
    return <AssetsPage />;
  }
  if (connectorId === 'sccm-cmdb') {
    return <SccmConnectorPage />;
  }
  if (connectorId === 'aws-discovery') {
    return <AwsDiscoveryConnectorPage />;
  }
  if (connectorId === 'azure-discovery') {
    return <AzureDiscoveryConnectorPage />;
  }
  if (connectorId === 'ai-security-aws') {
    return <AiSecurityConnectorPage />;
  }
  if (connectorId === 'ai-security-azure') {
    return <AiSecurityAzureConnectorPage />;
  }
  if (connectorId === 'ai-security-copilot') {
    return <CopilotStudioConnectorPage />;
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Connector Setup</h3>
        <span className="panel-caption">This connector detail page is reserved for Phase 2 integration.</span>
      </div>
      <div className="empty-state">
        <p>Connector scaffolding is ready. Detailed authentication, test connection, and scheduling controls will be added here.</p>
      </div>
    </section>
  );
}

type ConnectPageProps = {
  initialView?: ConnectView;
  onViewChange?: (view: ConnectView) => void;
};

export function ConnectPage(props: ConnectPageProps = {}) {
  const actor = useActor();
  if (hasRole(actor, 'PLATFORM_OWNER') && !actor?.tenantId) return <Navigate to={pathForPlatformView('vuln-intel')} replace />;
  return <TenantConnectPage {...props} />;
}

function TenantConnectPage({ initialView = 'sources', onViewChange }: ConnectPageProps) {
  const actor = useActor();
  const inventoryConnectorsDisabledForDemo = actor?.demoCapabilities?.liveConnectors === false;
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeView, setActiveView] = React.useState<ConnectView>(initialView);
  // The catalog is also the allowlist for bookmarks and browser navigation.
  const activeConnector = readConnectorFromSearch(searchParams);
  const setActiveConnector = React.useCallback((connectorId: ConnectorId | null) => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete(CONNECT_SOURCE_QUERY_KEY);
    if (connectorId) nextParams.set(CONNECT_SOURCE_QUERY_KEY, connectorId);
    setSearchParams(nextParams, { replace: true });
  }, [searchParams, setSearchParams]);
  const [vulnIntelCollapsed, setVulnIntelCollapsed] = React.useState(false);
  const serviceNowConfigQuery = useServiceNowCmdbConfigQuery();
  const sccmConfigQuery = useSccmCmdbConfigQuery();
  const awsConfigQuery = useAwsDiscoveryConfigQuery();
  const azureConfigQuery = useAzureDiscoveryConfigQuery();
  const snConfig = serviceNowConfigQuery.data ?? null;
  const sccmConfig = sccmConfigQuery.data ?? null;
  const awsConfig = awsConfigQuery.data ?? null;
  const azureConfig = azureConfigQuery.data ?? null;

  React.useEffect(() => {
    setActiveView(initialView);
  }, [initialView]);

  React.useEffect(() => {
    if (searchParams.has(CONNECT_SOURCE_QUERY_KEY) && !activeConnector) {
      setActiveConnector(null);
    }
  }, [activeConnector, searchParams, setActiveConnector]);

  const selectedConnector = activeConnector ? CONNECTORS.find((connector) => connector.id === activeConnector) ?? null : null;
  const selectedConnectorAllowed = selectedConnector != null
    && !VULNERABILITY_INTELLIGENCE_CONNECTOR_IDS.includes(selectedConnector.id);

  React.useEffect(() => {
    if (!activeConnector) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActiveConnector(null);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeConnector, setActiveConnector]);

  const aiEntitled = canUseEntitlement(actor, 'ai.security');
  const inventoryConnectors = INVENTORY_CONNECTOR_IDS
    .filter((id) => aiEntitled || !AI_CONNECTOR_IDS.includes(id))
    .map((id) => CONNECTORS.find((connector) => connector.id === id))
    .filter((connector): connector is ConnectorDefinition => Boolean(connector));
  const bomConnectors = BOM_CONNECTOR_IDS
    .map((id) => CONNECTORS.find((connector) => connector.id === id))
    .filter((connector): connector is ConnectorDefinition => Boolean(connector));

  const visibleSections = [
    {
      key: 'inventory' as const,
      title: 'Inventory',
      connectors: inventoryConnectors,
      caption: 'SBOM, CMDB, Cloud discovery, and AI resource inventory sources.',
    },
    {
      key: 'bom-management' as const,
      title: 'BOM Management',
      connectors: bomConnectors,
      caption: 'Ingest and manage Bill of Materials files.',
    }
  ];

  return (
    <div className="page-grid ui2-connect-family">
      <div className="connect-filter-bar connect-filter-bar--standalone">
        {CONNECT_VIEW_ORDER.map((view) => (
          <button
            key={view}
            type="button"
            className={`connect-filter-btn${activeView === view ? ' active' : ''}`}
            onClick={() => {
              setActiveView(view);
              if (view !== 'sources') {
                setActiveConnector(null);
              }
              onViewChange?.(view);
            }}
          >
            {view === 'sources' && 'Sources'}
            {view === 'run-history' && 'Run History'}
          </button>
        ))}
      </div>

      {activeView === 'sources' && !activeConnector && (
        <section className="panel connect-catalog-panel">
          <div className="connect-sections-layout">
            {visibleSections.map((section) => (
                <div key={section.key} className="connect-source-section">
                  <div className="connect-source-section-head">
                    <h4>{section.title}</h4>
                    <span className="panel-caption">{section.caption}</span>
                  </div>
                  {section.connectors.length === 0 ? (
                    <div className="empty-state">
                      <p>No sources in this section match the search.</p>
                    </div>
                  ) : (
                    <div className="connect-card-grid">
                      {section.connectors.map((connector) => {
                        const status =
                          connector.id === 'servicenow-cmdb' ? buildInventoryConnectorStatus(snConfig, inventoryConnectorsDisabledForDemo) :
                          connector.id === 'sccm-cmdb' ? buildInventoryConnectorStatus(sccmConfig, inventoryConnectorsDisabledForDemo) :
                          connector.id === 'aws-discovery' ? buildInventoryConnectorStatus(awsConfig, inventoryConnectorsDisabledForDemo) :
                          connector.id === 'azure-discovery' ? buildInventoryConnectorStatus(azureConfig, inventoryConnectorsDisabledForDemo) :
                          buildInventoryConnectorStatus(null, inventoryConnectorsDisabledForDemo);
                        const lastSync = timeAgo(status.lastSyncAt);

                        const dotClass = status.isFailed ? 'connect-source-dot--fail' :
                                         status.hasSynced ? 'connect-source-dot--ok' :
                                         'connect-source-dot--warn';
                        const statusTitle = status.demoDisabled ? 'Unavailable in 7-day demo'
                          : status.isFailed ? `Last sync failed${lastSync ? ` · ${lastSync}` : ''}`
                          : lastSync ? `Last sync · ${lastSync}`
                          : 'Not configured';

                        return (
                          <button
                            key={connector.id}
                            type="button"
                            className={`connect-source-card${activeConnector === connector.id ? ' connect-source-card--active' : ''}${status.demoDisabled ? ' connect-source-card--disabled' : ''}`}
                            onClick={() => setActiveConnector(connector.id)}
                          >
                            <div className="connect-source-icon" aria-hidden="true">{connector.icon}</div>
                            <div className="connect-source-body">
                              <div className="connect-source-name-row">
                                <span className="connect-source-name">{connector.name}</span>
                                {/* The dot is the only place connector health appears in this
                                    layout, so its title carries the detail the old stacked card
                                    showed as text. Dropping it would lose at-a-glance sync
                                    state for every connector. */}
                                <span
                                  className={`connect-source-dot ${dotClass}`}
                                  title={statusTitle}
                                  aria-label={statusTitle}
                                  role="img"
                                />
                              </div>
                              <div className="panel-caption">{connector.summary}</div>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}

            {/* Vulnerability Intelligence — 3rd section */}
            <div className="connect-source-section">
              <button
                type="button"
                className="config-accordion-toggle"
                aria-expanded={!vulnIntelCollapsed}
                onClick={() => setVulnIntelCollapsed((c) => !c)}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, textAlign: 'left' }}>
                  <span>Vulnerability Intelligence</span>
                  {vulnIntelCollapsed && (
                    <span className="panel-caption" style={{ fontWeight: 400 }}>
                      Select which ingested sources drive tenant correlation while keeping the broader repository visible for research.
                    </span>
                  )}
                </div>
                <svg className={`config-chevron${vulnIntelCollapsed ? '' : ' open'}`} width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
              {!vulnIntelCollapsed && (
                <>
                  <div className="connect-source-section-head" style={{ marginTop: 4 }}>
                    <span className="panel-caption">
                      Select which ingested sources drive tenant correlation while keeping the broader repository visible for research.
                    </span>
                  </div>
                  <VulnerabilitySourcesSection canEdit={canManageSourceFilters(actor)} />
                </>
              )}
            </div>
          </div>
        </section>
      )}

      {activeView === 'run-history' && <InventoryRunQueuePage />}

      {activeConnector && selectedConnector && !selectedConnectorAllowed && (
        <section className="panel">
          <div className="notice" role="note">
            Central vulnerability repository feeds are platform-owned. Sign in as a Platform Owner to manage NVD, KEV, GHSA, CSAF/VEX, advisory, or EOL sources.
          </div>
          <button type="button" className="btn btn-secondary" onClick={() => setActiveConnector(null)}>
            Back to customer sources
          </button>
        </section>
      )}

      {activeConnector && selectedConnector && selectedConnectorAllowed && (
        <section className="panel">
          <div className="connector-page-back-row">
            <button
              type="button"
              className="btn-link"
              onClick={() => setActiveConnector(null)}
            >
              ← Back to Sources
            </button>
            <span className="connector-page-title">{selectedConnector.name}</span>
          </div>
          <ConnectorDetailContent connectorId={activeConnector} />
        </section>
      )}
    </div>
  );
}
