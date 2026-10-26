import { useMutation, useQuery } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import type { Finding } from '../features/findings/types';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForFindingDetail, pathForInventoryHostAsset, pathForInventoryView, pathForVulnRepoView } from '../app/routes';
import { api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { FixRecord, OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import { useVulnRepoVulnerabilitiesQuery } from '../features/cve-workbench/queries';
import { useSoftwareIdentityDetailQuery, useSoftwareIdentityMetadataQuery } from '../features/software-identities/queries';
import type { SoftwareIdentityAsset, SoftwareIdentityDetail, SoftwareIdentityMetadata } from '../features/software-identities/types';

type Props = {
  softwareIdentityId: string;
};

type DetailTab = 'versions' | 'assets' | 'vulnerabilities' | 'findings' | 'fixes';

const VERSION_COLUMNS: DataTableColumn[] = [
  { id: 'version', label: 'Version', header: 'Version', initialSize: 180 },
  { id: 'hosts', label: 'Installed Hosts', header: 'Installed Hosts', initialSize: 140 },
  { id: 'assets', label: 'Assets', header: 'Assets', initialSize: 110 },
  { id: 'rows', label: 'Rows', header: 'Rows', initialSize: 90 },
  { id: 'cves', label: 'CVEs', header: 'CVEs', initialSize: 90 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'lifecycle', label: 'Lifecycle', header: 'Lifecycle', initialSize: 150 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 170 }
];

const ASSET_COLUMNS_BASE: DataTableColumn[] = [
  { id: 'select', label: '', header: '', initialSize: 48 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 260 },
  { id: 'package', label: 'Package', header: 'Package', initialSize: 160 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 150 },
  { id: 'cves', label: 'CVEs', header: 'CVEs', initialSize: 90 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'type', label: 'Type', header: 'Type', initialSize: 110 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 130 },
];

const VULNERABILITY_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 170 },
  { id: 'title', label: 'Description', header: 'Description', initialSize: 380 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'matchedAssets', label: 'Assets', header: 'Assets', initialSize: 90 },
  { id: 'applicable', label: 'Applicable Components', header: 'Applicable Components', initialSize: 160 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 130 },
  { id: 'lastEvaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 170 }
];

const FINDING_COLUMNS: DataTableColumn[] = [
  { id: 'findingId', label: 'Finding ID', header: 'Finding ID', initialSize: 120 },
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 170 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 240 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 110 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 130 },
  { id: 'package', label: 'Package', header: 'Package', initialSize: 160 },
  { id: 'dueAt', label: 'Due Date', header: 'Due Date', initialSize: 140 },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 170 },
];

function defaultMetadata(softwareIdentityId = ''): SoftwareIdentityMetadata {
  return {
    softwareIdentityId,
    owner: '',
    licensed: 'Unknown',
    licenseType: '',
    supportGroup: '',
    recommendation: ''
  };
}

function formatDateTime(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '-' : parsed.toLocaleString();
}

function lifecycleLabel(eolCount: number, nearEolCount: number, unknownCount: number): string {
  if (eolCount > 0) return `${eolCount.toLocaleString()} EOL`;
  if (nearEolCount > 0) return `${nearEolCount.toLocaleString()} near EOL`;
  if (unknownCount > 0) return `${unknownCount.toLocaleString()} unknown lifecycle`;
  return 'Supported';
}

function formatBomLabel(value?: string): string {
  if (!value) return '-';
  return value.replace(/_/g, ' ');
}

function _lifecycleClassName(detail: SoftwareIdentityDetail): string {
  if (detail.eolComponentCount > 0) return 'status-pill status-failure';
  if (detail.nearEolComponentCount > 0) return 'status-pill status-warning';
  if (detail.unknownEolComponentCount > 0) return 'status-pill status-unknown';
  return 'status-pill status-success';
}

function extractAiRecommendation(response: { recommendation?: string; data?: Record<string, unknown> }): string {
  const data = response.data;
  const bottomLine = data?.bottom_line;
  if (bottomLine && typeof bottomLine === 'object') {
    const summary = (bottomLine as { summary?: unknown }).summary;
    if (typeof summary === 'string' && summary.trim()) return summary.trim();
  }
  const immediate = data?.immediate_action;
  if (immediate && typeof immediate === 'object') {
    const action = (immediate as { action?: unknown }).action;
    if (typeof action === 'string' && action.trim()) return action.trim();
  }
  if (response.recommendation?.trim()) return response.recommendation.trim();
  return 'No recommendation was returned.';
}

function timeAgo(value?: string): string {
  if (!value) return 'unknown';
  const diff = Date.now() - new Date(value).getTime();
  if (diff < 0) return 'just now';
  const hours = Math.floor(diff / 3_600_000);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(diff / 86_400_000);
  return `${days}d ago`;
}

function buildFallbackRecommendation(detail: SoftwareIdentityDetail, vulnerabilities: OrgSpecificCveExposureRecord[]): string {
  const parts: string[] = [];
  const criticalCount = detail.assets.filter(isCriticalAsset).length;
  const eolVersions = detail.versions.filter((v) => v.isEol);
  const nearEolVersions = detail.versions.filter((v) => !v.isEol && v.eolDaysRemaining != null && v.eolDaysRemaining <= 90);
  const supportedVersions = detail.versions.filter((v) => !v.isEol && (v.eolDaysRemaining == null || v.eolDaysRemaining > 90) && v.eolSlug);

  parts.push(
    `${detail.displayName} is installed on ${detail.assetCount.toLocaleString()} asset${detail.assetCount !== 1 ? 's' : ''}` +
    (criticalCount > 0 ? `, including ${criticalCount} critical asset${criticalCount !== 1 ? 's' : ''}` : '') +
    `, with ${detail.openVulnerabilityCount.toLocaleString()} open CVE${detail.openVulnerabilityCount !== 1 ? 's' : ''}.`
  );

  const topCves = vulnerabilities.slice(0, 3).map((v) => v.externalId);
  if (topCves.length > 0) {
    parts.push(`Highest-priority vulnerabilities to remediate: ${topCves.join(', ')}.`);
  }

  if (eolVersions.length > 0) {
    const eolList = eolVersions.slice(0, 3).map((v) => v.version).join(', ');
    parts.push(`${eolVersions.length} EOL version${eolVersions.length !== 1 ? 's' : ''} detected (${eolList}) — these no longer receive security patches and must be upgraded immediately.`);
  } else if (nearEolVersions.length > 0) {
    parts.push(`${nearEolVersions.length} version${nearEolVersions.length !== 1 ? 's are' : ' is'} approaching end-of-life within 90 days — schedule upgrades promptly.`);
  }

  if (supportedVersions.length > 0) {
    parts.push(`Recommended upgrade target: version ${supportedVersions[0].version} (actively supported).`);
  } else if (detail.eolSlug) {
    parts.push(`Consult the ${detail.eolSlug} release schedule to identify the latest supported version.`);
  }

  parts.push(`After upgrading: re-run vulnerability scans, validate application functionality, update the CMDB record, and close or reassign open findings resolved by the upgrade.`);

  return parts.join(' ');
}

function buildSoftwareRecommendationPrompt(
  detail: SoftwareIdentityDetail,
  cve: Pick<OrgSpecificCveExposureRecord, 'externalId' | 'title' | 'severity' | 'cvssScore'> | null,
  affectedAssets: number,
  environmentContext: string
): string {
  const productLabel = [detail.displayName, detail.product ? `version ${detail.product}` : null].filter(Boolean).join(' ');
  const cveLine = cve
    ? `Vulnerability/CVE: ${cve.externalId} - ${cve.title}`
    : 'Vulnerability/CVE: No specific CVE selected; generate a software-level remediation recommendation.';
  const cvss = cve?.cvssScore != null ? `${cve.cvssScore.toFixed(1)}` : 'unknown';

  return [
    'You are a cybersecurity remediation advisor writing for an enterprise IT operations team. Generate a concise, actionable remediation recommendation for the following software vulnerability.',
    'Input details:',
    '',
    `Software/Product: ${productLabel || 'unknown'}`,
    cveLine,
    `Severity (CVSS): ${cve?.severity ?? 'UNKNOWN'}${cvss === 'unknown' ? '' : ` (${cvss})`}`,
    `Number of affected assets: ${affectedAssets.toLocaleString()}`,
    `Environment context (optional): ${environmentContext || 'unknown'}`,
    '',
    'Produce a recommendation with these sections:',
    '',
    'Risk summary (2–3 sentences): What the vulnerability is, what an attacker could do, and why it matters given the asset count and exposure.',
    'Primary remediation: The vendor-recommended fix (specific patch version, security update, or upgrade path). Include version numbers and links to vendor advisories where applicable.',
    'Compensating controls (if patching is delayed): Network segmentation, WAF/IPS rules, access restrictions, disabling vulnerable features, or monitoring guidance.',
    'Verification steps: How the IT team can confirm the fix was applied successfully (e.g., version check command, vulnerability rescan).',
    'Priority and SLA: Recommended urgency (Critical/High/Medium/Low) and target remediation window based on severity and exposure.',
    'Rollback considerations: Known compatibility issues, dependencies, or pre-patch testing steps.',
    '',
    'Keep the tone direct and operational. Avoid generic advice — tie every step to this specific CVE and software version. If information is unknown, state the assumption clearly rather than fabricating details.',
    'Limit the final response to 200 words or fewer.'
  ].join('\n');
}

export function SoftwareIdentityDetailPage({ softwareIdentityId }: Props) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = React.useState<DetailTab>('versions');
  const [findingMessage, setFindingMessage] = React.useState('');
  const [metadata, setMetadata] = React.useState<SoftwareIdentityMetadata>(() => defaultMetadata(softwareIdentityId));
  const [draftMetadata, setDraftMetadata] = React.useState<SoftwareIdentityMetadata>(() => defaultMetadata(softwareIdentityId));
  const [showFindingConfig, setShowFindingConfig] = React.useState(false);
  const [findingPriority, setFindingPriority] = React.useState('Medium');
  const [findingDueDate, setFindingDueDate] = React.useState(() => {
    const date = new Date();
    date.setDate(date.getDate() + 30);
    return date.toISOString().slice(0, 10);
  });
  const [findingTags, setFindingTags] = React.useState('');
  const [findingAssignment, setFindingAssignment] = React.useState('Assign to lead analyst');
  const [createServiceNowTickets, setCreateServiceNowTickets] = React.useState(true);
  const [findingNotes, setFindingNotes] = React.useState('');
  const [selectedCves, setSelectedCves] = React.useState<Set<string>>(new Set());
  const [selectedComponentIds, setSelectedComponentIds] = React.useState<Set<string>>(new Set());
  const [modalRecommendation, setModalRecommendation] = React.useState('');
  const [isEditingRec, setIsEditingRec] = React.useState(false);
  const [draftVendor, setDraftVendor] = React.useState('');

  const detailQuery = useSoftwareIdentityDetailQuery(softwareIdentityId);
  const metadataQuery = useSoftwareIdentityMetadataQuery(softwareIdentityId);
  // Omit includeAll so server returns only applicable CVEs for this software identity
  const vulnerabilitiesQuery = useVulnRepoVulnerabilitiesQuery({
    page: 0,
    size: 100,
    softwareIdentityId,
  });

  const detail = detailQuery.data ?? null;
  const vulnerabilities = React.useMemo(
    () => vulnerabilitiesQuery.data?.items ?? [],
    [vulnerabilitiesQuery.data?.items]
  );

  const findingsQuery = useQuery({
    queryKey: ['software-identity-findings', softwareIdentityId, detail?.product],
    queryFn: () => api.listFindings({ packageName: detail?.product ?? '', size: 200 }),
    enabled: Boolean(detail?.product),
  });
  const findings = React.useMemo<Finding[]>(
    () => findingsQuery.data?.items ?? [],
    [findingsQuery.data?.items]
  );

  const fixRecordsQuery = useQuery({
    queryKey: ['software-identity-fixes', detail?.product],
    queryFn: () => cveWorkbenchApi.getFixRecordsBySoftware(detail?.product ?? ''),
    enabled: Boolean(detail?.product),
  });

  React.useEffect(() => {
    const next = metadataQuery.data ?? defaultMetadata(softwareIdentityId);
    setMetadata(next);
    setDraftMetadata(next);
  }, [metadataQuery.data, softwareIdentityId]);

  React.useEffect(() => {
    if (detail?.vendor) setDraftVendor(detail.vendor);
  }, [detail?.vendor]);


  const saveMetadataMutation = useMutation({
    mutationFn: (next: SoftwareIdentityMetadata) => api.saveSoftwareIdentityMetadata(softwareIdentityId, {
      owner: next.owner,
      licensed: next.licensed,
      licenseType: next.licenseType,
      supportGroup: next.supportGroup,
      recommendation: next.recommendation
    }),
    onSuccess: (saved) => {
      setMetadata(saved);
      setDraftMetadata(saved);
      setFindingMessage('Software metadata saved.');
      void metadataQuery.refetch();
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to save software metadata.');
    }
  });

  // Select ALL applicable CVEs by default when they load
  React.useEffect(() => {
    if (selectedCves.size === 0 && vulnerabilities.length > 0) {
      setSelectedCves(new Set(vulnerabilities.map((v) => v.externalId)));
    }
  }, [selectedCves.size, vulnerabilities]);

  const _selectedAssets = React.useMemo(
    () => (detail?.assets ?? []).filter((asset) => selectedComponentIds.has(asset.componentId)),
    [detail?.assets, selectedComponentIds]
  );

  const selectedCveRecords = React.useMemo(
    () => vulnerabilities.filter((item) => selectedCves.has(item.externalId)),
    [selectedCves, vulnerabilities]
  );

  const generateRecommendationMutation = useMutation({
    mutationFn: async () => {
      if (!detail) throw new Error('Software identity is not loaded.');
      const primaryCve = vulnerabilities[0] ?? null;
      const eolVersionsList = detail.versions.filter((v) => v.isEol);
      const nearEolVersionsList = detail.versions.filter((v) => !v.isEol && v.eolDaysRemaining != null && v.eolDaysRemaining <= 90);
      const supportedVersionsList = detail.versions.filter((v) => !v.isEol && (v.eolDaysRemaining == null || v.eolDaysRemaining > 90) && v.eolSlug);
      const criticalAssetsList = detail.assets.filter(isCriticalAsset);
      const environmentContext = detail.sourceSystems.length > 0 ? detail.sourceSystems.join(', ') : 'unknown';
      const softwareRecommendationPrompt = buildSoftwareRecommendationPrompt(
        detail,
        primaryCve,
        detail.assetCount,
        environmentContext
      );
      const response = await cveWorkbenchApi.generateAiSolution(primaryCve?.externalId ?? `software-${detail.id}`, {
        softwareRecommendationPrompt,
        severity: primaryCve?.severity ?? (detail.openVulnerabilityCount > 0 ? 'MEDIUM' : 'LOW'),
        affected_assets: detail.assetCount,
        vulnerability: {
          id: primaryCve?.externalId ?? detail.canonicalKey,
          summary: primaryCve ? (primaryCve.descriptionSnippet || primaryCve.title) : `${detail.displayName} software-level recommendation`
        },
        software: {
          id: detail.id,
          name: detail.displayName,
          vendor: detail.vendor,
          product: detail.product,
          owner: metadata.owner || null,
          licensed: metadata.licensed,
          license_type: metadata.licenseType || null,
          support_group: metadata.supportGroup || null,
          lifecycle: lifecycleLabel(detail.eolComponentCount, detail.nearEolComponentCount, detail.unknownEolComponentCount),
          installed_asset_count: detail.assetCount,
          installed_software_rows: detail.componentCount,
          eol_version_count: eolVersionsList.length,
          eol_versions: eolVersionsList.slice(0, 5).map((v) => v.version),
          near_eol_version_count: nearEolVersionsList.length,
          recommended_upgrade_version: supportedVersionsList[0]?.version ?? null,
          eol_slug: detail.eolSlug ?? null,
        },
        selected_cves: vulnerabilities.map((item) => ({
          cve: item.externalId,
          severity: item.severity,
          cvss_score: item.cvssScore,
          applicable_components: item.applicableComponentCount,
          open_findings: item.openFindings
        })),
        selected_assets: detail.assets.slice(0, 20).map((asset) => ({
          name: asset.assetName,
          type: asset.assetType,
          version: asset.version,
          open_cves: asset.openVulnerabilityCount,
          open_findings: asset.openFindingCount,
          is_critical: isCriticalAsset(asset),
          is_eol: asset.isEol ?? false,
        })),
          critical_asset_count: criticalAssetsList.length,
          post_upgrade_actions: [
            'Re-run vulnerability scans after upgrade',
            'Validate application functionality and integration points',
            'Update CMDB with new version details',
          'Close or reassign open findings resolved by the upgrade',
          'Notify application owner and support group of completion',
        ],
      });
      return extractAiRecommendation(response);
    },
    onSuccess: (recommendation) => {
      // Update the draft textarea only — user must explicitly save
      setDraftMetadata((prev) => ({ ...prev, recommendation }));
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to generate AI recommendation.');
    }
  });

  const createFindingsMutation = useMutation({
    mutationFn: async () => {
      if (selectedCveRecords.length === 0) throw new Error('Select at least one CVE.');
      if (selectedComponentIds.size === 0) throw new Error('Select at least one asset.');
      const recommendation = modalRecommendation.trim()
        || metadata.recommendation?.trim()
        || (detail ? buildFallbackRecommendation(detail, selectedCveRecords) : '');
      const componentIds = Array.from(selectedComponentIds);
      const results = await Promise.all(selectedCveRecords.map((record) =>
        cveWorkbenchApi.createManualFindings(record.externalId, {
          justification: [
            `Created from software record ${detail?.displayName ?? softwareIdentityId}.`,
            `Priority: ${findingPriority}`,
            `Due date: ${findingDueDate || 'Not set'}`,
            findingTags.trim() ? `Tags: ${findingTags.trim()}` : null,
            `Assignment: ${findingAssignment}`,
            `Create ServiceNow tickets: ${createServiceNowTickets ? 'Yes' : 'No'}`,
            findingNotes.trim() ? `Notes: ${findingNotes.trim()}` : null,
            recommendation ? `Recommendation: ${recommendation}` : null
          ].filter(Boolean).join('\n\n'),
          componentIds,
          componentApplicabilityDecisions: Object.fromEntries(componentIds.map((id) => [id, 'APPLICABLE'])),
          componentAnalystDispositions: Object.fromEntries(componentIds.map((id) => [id, 'IMPACTED']))
        })
      ));
      return results;
    },
    onSuccess: (responses) => {
      const created = responses.reduce((sum, response) => sum + response.createdCount + response.reopenedCount, 0);
      const alreadyOpen = responses.reduce((sum, response) => sum + response.alreadyOpenCount, 0);
      setFindingMessage(`Created or reopened ${created.toLocaleString()} findings. ${alreadyOpen.toLocaleString()} were already open.`);
      setShowFindingConfig(false);
      void vulnerabilitiesQuery.refetch();
      void detailQuery.refetch();
    },
    onError: (error) => {
      setFindingMessage(error instanceof Error ? error.message : 'Failed to create findings.');
    }
  });

  const toggleCve = React.useCallback((externalId: string) => {
    setSelectedCves((current) => {
      const next = new Set(current);
      if (next.has(externalId)) next.delete(externalId);
      else next.add(externalId);
      return next;
    });
  }, []);

  const toggleComponent = React.useCallback((componentId: string) => {
    setSelectedComponentIds((current) => {
      const next = new Set(current);
      if (next.has(componentId)) next.delete(componentId);
      else next.add(componentId);
      return next;
    });
  }, []);

  const allAssetIds = React.useMemo(() => (detail?.assets ?? []).map((a) => a.componentId), [detail?.assets]);
  const allAssetsSelected = allAssetIds.length > 0 && allAssetIds.every((id) => selectedComponentIds.has(id));
  const someAssetsSelected = !allAssetsSelected && allAssetIds.some((id) => selectedComponentIds.has(id));

  const toggleAllAssets = React.useCallback(() => {
    setSelectedComponentIds((current) => {
      const allSelected = allAssetIds.every((id) => current.has(id));
      return allSelected ? new Set() : new Set(allAssetIds);
    });
  }, [allAssetIds]);

  const assetColumns = React.useMemo<DataTableColumn[]>(() => [
    {
      ...ASSET_COLUMNS_BASE[0],
      header: (
        <input
          type="checkbox"
          checked={allAssetsSelected}
          ref={(el) => { if (el) el.indeterminate = someAssetsSelected; }}
          onChange={toggleAllAssets}
          aria-label="Select all assets"
        />
      ),
    },
    ...ASSET_COLUMNS_BASE.slice(1),
  ], [allAssetsSelected, someAssetsSelected, toggleAllAssets]);

  const versionRows = React.useMemo<DataTableRow[]>(() => (detail?.versions ?? []).map((version) => ({
    id: version.version || 'unknown-version',
    cells: {
      version: { content: version.version || '-' },
      hosts: { content: version.assetCount.toLocaleString() },
      assets: { content: version.assetCount.toLocaleString() },
      rows: { content: version.componentCount.toLocaleString() },
      cves: { content: version.openVulnerabilityCount.toLocaleString() },
      findings: { content: version.openFindingCount.toLocaleString() },
      lifecycle: {
        content: version.isEol
          ? <span className="status-pill status-failure">EOL</span>
          : version.eolDaysRemaining != null && version.eolDaysRemaining <= 90
            ? <span className="status-pill status-warning">Near EOL</span>
            : version.eolSlug
              ? <span className="status-pill status-success">Supported</span>
              : <span className="status-pill status-unknown">Unknown</span>
      },
      lastObserved: { content: formatDateTime(version.lastObservedAt) }
    }
  })), [detail?.versions]);

  const assetRows = React.useMemo<DataTableRow[]>(() => (detail?.assets ?? []).map((asset) => ({
    id: asset.componentId,
    cells: {
      select: {
        content: (
          <input
            type="checkbox"
            checked={selectedComponentIds.has(asset.componentId)}
            onChange={() => toggleComponent(asset.componentId)}
            aria-label={`Select ${asset.assetName}`}
          />
        )
      },
      asset: {
        content: (
          <>
            <button
              type="button"
              className="btn-link"
              onClick={() => navigate(pathForInventoryHostAsset(asset.assetId, `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`))}
            >
              {asset.assetName}
            </button>
            <div className="panel-caption mono">{asset.assetIdentifier}</div>
          </>
        )
      },
      type: { content: asset.assetType },
      package: { content: asset.packageName },
      version: { content: asset.version || '-' },
      source: { content: asset.sourceSystem || '-' },
      cves: { content: asset.openVulnerabilityCount.toLocaleString() },
      findings: { content: asset.openFindingCount.toLocaleString() },
      lastObserved: { content: formatDateTime(asset.lastObservedAt) }
    }
  })), [detail?.assets, navigate, selectedComponentIds, softwareIdentityId, toggleComponent]);

  const vulnerabilityRows = React.useMemo<DataTableRow[]>(() => vulnerabilities.map((item) => ({
    id: item.recordId,
    cells: {
      cve: {
        content: (
          <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}>
            <span className="mono">{item.externalId}</span>
          </button>
        )
      },
      title: { content: item.descriptionSnippet?.trim() || item.title },
      severity: { content: <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span> },
      matchedAssets: { content: item.matchedAssetCount.toLocaleString() },
      applicable: { content: item.applicableComponentCount.toLocaleString() },
      openFindings: { content: item.openFindings.toLocaleString() },
      lastEvaluated: { content: formatDateTime(item.lastEvaluatedAt) }
    }
  })), [navigate, vulnerabilities]);

  const findingRows = React.useMemo<DataTableRow[]>(() => findings.map((f) => ({
    id: f.id,
    cells: {
      findingId: {
        content: (
          <button
            type="button"
            className="btn-link mono"
            style={{ fontSize: '0.8rem' }}
            onClick={() => navigate(
              pathForFindingDetail(f.displayId || f.id, `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`),
              { state: { finding: f } }
            )}
          >
            {f.displayId || f.id.slice(0, 8)}
          </button>
        )
      },
      cve: {
        content: (
          <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('org-cves', f.vulnerabilityId))}>
            <span className="mono">{f.vulnerabilityId}</span>
          </button>
        )
      },
      asset: {
        content: (
          <>
            <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryHostAsset(f.componentId, `/inventory/software-identities/${encodeURIComponent(softwareIdentityId)}`))}>
              {f.assetName}
            </button>
            <div className="panel-caption mono">{f.assetIdentifier}</div>
          </>
        )
      },
      severity: { content: <span className={severityClassName(f.severity)}>{formatLabel(f.severity)}</span> },
      status: { content: <span className={`status-pill ${f.status === 'OPEN' ? 'status-open' : f.status === 'RESOLVED' ? 'status-success' : 'status-unknown'}`}>{formatLabel(f.status)}</span> },
      package: { content: `${f.packageName} ${f.packageVersion}`.trim() },
      dueAt: { content: formatDateTime(f.dueAt) },
      lastObserved: { content: formatDateTime(f.lastObservedAt) },
    }
  })), [findings, navigate, softwareIdentityId]);

  if (detailQuery.isLoading) {
    return <div className="notice">Loading software identity...</div>;
  }

  if (detailQuery.error instanceof Error) {
    return <div className="notice error">{detailQuery.error.message}</div>;
  }

  if (!detail) {
    return <div className="notice error">Software identity was not found.</div>;
  }

  const latestDataUpdate = latestFreshnessValue([
    detailQuery.dataUpdatedAt,
    metadataQuery.dataUpdatedAt,
    vulnerabilitiesQuery.dataUpdatedAt,
    findingsQuery.dataUpdatedAt,
    fixRecordsQuery.dataUpdatedAt,
    detail.lastObservedAt,
    metadata.updatedAt,
    metadata.recommendationUpdatedAt,
  ]);
  const detailRefreshing = [
    detailQuery,
    metadataQuery,
    vulnerabilitiesQuery,
    findingsQuery,
    fixRecordsQuery
  ].some((query) => query.isFetching);
  const criticalAssets = detail.assets.filter(isCriticalAsset);
  const eolVersionCount = detail.versions.filter((version) => version.isEol || (version.eolDaysRemaining != null && version.eolDaysRemaining <= 90)).length;
  const bomEvidence = detail.bomEvidence;

  const needsAttention: { key: string; title: string; description: string; onClick: () => void }[] = [];
  if (detail.openVulnerabilityCount > 0) {
    needsAttention.push({
      key: 'open-cves',
      title: 'Review open CVEs',
      description: `${detail.openVulnerabilityCount.toLocaleString()} open CVE${detail.openVulnerabilityCount !== 1 ? 's' : ''} matched to this software.`,
      onClick: () => setActiveTab('vulnerabilities'),
    });
  }
  if (detail.openFindingCount > 0) {
    needsAttention.push({
      key: 'open-findings',
      title: 'Review open findings',
      description: `${detail.openFindingCount.toLocaleString()} open finding${detail.openFindingCount !== 1 ? 's' : ''} tied to this software.`,
      onClick: () => setActiveTab('findings'),
    });
  }
  if (eolVersionCount > 0) {
    needsAttention.push({
      key: 'eol-versions',
      title: 'Update EOL versions',
      description: `${eolVersionCount.toLocaleString()} version${eolVersionCount !== 1 ? 's are' : ' is'} end-of-life or approaching EOL.`,
      onClick: () => setActiveTab('versions'),
    });
  }
  if (criticalAssets.length > 0 && vulnerabilities.length > 0) {
    needsAttention.push({
      key: 'critical-assets',
      title: 'Critical assets affected',
      description: `${criticalAssets.length.toLocaleString()} critical asset${criticalAssets.length !== 1 ? 's are' : ' is'} exposed · top: ${vulnerabilities[0].externalId}.`,
      onClick: () => navigate(pathForVulnRepoView('org-cves', vulnerabilities[0].externalId)),
    });
  }

  const tabLabel = activeTab === 'versions' ? 'Versions'
    : activeTab === 'assets' ? 'Installed Assets'
    : activeTab === 'vulnerabilities' ? 'CVEs'
    : activeTab === 'findings' ? 'Findings'
    : 'Fixes';

  return (
    <section className="inventory-page-shell software-detail-page">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={detailRefreshing}
        refreshLabel="Refreshing software identity details while keeping current context visible…"
      />

      <button type="button" className="btn-link sdi-back-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>
        ← Back to Software Entities
      </button>

      <div className="fd3-topbar">
        <span aria-hidden="true">📦</span>
        <span className="fd3-finding-id mono">
          {detail.vendor && detail.product && detail.vendor.toLowerCase() !== detail.product.toLowerCase() ? (
            <>
              <span className="sdi-title-vendor">{detail.vendor}</span>
              <span className="sdi-title-sep">/</span>
              <span className="sdi-title-product">{detail.product}</span>
            </>
          ) : (
            <span className="sdi-title-product">{detail.displayName}</span>
          )}
        </span>
        <span className="panel-caption">
          {detail.versionCount.toLocaleString()} {detail.versionCount === 1 ? 'version' : 'versions'} observed
          {detail.lastObservedAt ? <> · last seen <strong>{timeAgo(detail.lastObservedAt)}</strong></> : null}
          {detail.sourceSystems.length > 0 ? <> · discovered via <strong>{detail.sourceSystems[0]}</strong></> : null}
        </span>
        <div style={{ flex: 1 }} />
        <div className="fd3-actions">
          {detail.ecosystems[0] ? <span className="cvd-signal-pill">{detail.ecosystems[0]}</span> : null}
          <span className={`sdi-hero-pill ${eolVersionCount > 0 ? 'sdi-hero-pill--danger' : detail.nearEolComponentCount > 0 ? 'sdi-hero-pill--warn' : 'sdi-hero-pill--ok'}`}>
            {lifecycleLabel(detail.eolComponentCount, detail.nearEolComponentCount, detail.unknownEolComponentCount)}
          </span>
        </div>
      </div>

      <div className="fd3-tab-bar" role="tablist" aria-label="Software identity sections">
        {(['versions', 'assets', 'vulnerabilities', 'findings', 'fixes'] as DetailTab[]).map((tab) => (
          <button
            key={tab}
            type="button"
            className={`fd3-tab${activeTab === tab ? ' fd3-tab--active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'versions' ? 'Versions'
              : tab === 'assets' ? 'Installed Assets'
              : tab === 'vulnerabilities' ? 'CVEs'
              : tab === 'findings' ? 'Findings'
              : 'Fixes'}
            <span className="fd3-tab-count">
              {tab === 'versions' ? versionRows.length
                : tab === 'assets' ? assetRows.length
                : tab === 'vulnerabilities' ? vulnerabilityRows.length
                : tab === 'findings' ? findingRows.length
                : fixRecordsQuery.data?.length ?? 0}
            </span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <button
          type="button"
          className="btn btn-primary software-detail-create-findings-btn"
          disabled={selectedComponentIds.size === 0 || selectedCves.size === 0}
          onClick={() => {
            setModalRecommendation(metadata.recommendation?.trim() || (detail ? buildFallbackRecommendation(detail, vulnerabilities) : ''));
            setShowFindingConfig(true);
          }}
        >
          Create findings
        </button>
      </div>

      <div className="fd3-body">
        <div className="fd3-col fd3-col-right">
          <Panel title={tabLabel}>
            {activeTab === 'versions' ? (
              <TableOrEmpty rows={versionRows} columns={VERSION_COLUMNS} storageKey={`software-identity-versions:v2:${softwareIdentityId}`} empty="No versions are currently associated with this software identity." />
            ) : activeTab === 'assets' ? (
              <TableOrEmpty rows={assetRows} columns={assetColumns} storageKey={`software-identity-assets:v5:${softwareIdentityId}`} empty="No assets are currently associated with this software identity." />
            ) : activeTab === 'vulnerabilities' ? (
              vulnerabilitiesQuery.isLoading ? (
                <div className="notice">Loading CVEs...</div>
              ) : vulnerabilitiesQuery.error instanceof Error ? (
                <div className="notice error">{vulnerabilitiesQuery.error.message}</div>
              ) : (
                <TableOrEmpty rows={vulnerabilityRows} columns={VULNERABILITY_COLUMNS} storageKey={`software-identity-vulnerabilities:v2:${softwareIdentityId}`} empty="No CVEs are currently matched to this software identity." />
              )
            ) : activeTab === 'findings' ? (
              findingsQuery.isLoading ? (
                <div className="notice">Loading findings...</div>
              ) : findingsQuery.error instanceof Error ? (
                <div className="notice error">{findingsQuery.error.message}</div>
              ) : (
                <TableOrEmpty rows={findingRows} columns={FINDING_COLUMNS} storageKey={`software-identity-findings:v3:${softwareIdentityId}`} empty="No findings are currently tied to this software identity." />
              )
            ) : fixRecordsQuery.isLoading ? (
              <div className="notice">Loading fixes...</div>
            ) : fixRecordsQuery.error instanceof Error ? (
              <div className="notice error">{fixRecordsQuery.error.message}</div>
            ) : !fixRecordsQuery.data || fixRecordsQuery.data.length === 0 ? (
              <div className="notice">No fix records have been generated for this software yet. Generate fixes from the CVE Assessment Workbench.</div>
            ) : (
              <SoftwareFixRecordsTable fixes={fixRecordsQuery.data} />
            )}
          </Panel>
        </div>

        <div className="fd3-col fd3-col-left">
          {needsAttention.length > 0 && (
            <div className="fd3-panel">
              <div className="fd3-panel-title">Needs Attention</div>
              <div className="cvd2-wf-cards">
                {needsAttention.map((item, index) => (
                  <button key={item.key} type="button" className="cvd2-wf-card" onClick={item.onClick}>
                    <div className="cvd2-wf-card-num">{index + 1}</div>
                    <div className="cvd2-wf-card-body">
                      <div className="cvd2-wf-card-title-row">
                        <span className="cvd2-wf-card-title">{item.title}</span>
                      </div>
                      <p className="cvd2-wf-card-sub">{item.description}</p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          <Panel title="Remediation recommendation">
            <div className="sdi-briefing-card">
              <div className="sdi-briefing-header">
                <h3 className="sdi-briefing-title">What to do about this software</h3>
              </div>
              <div className="sdi-briefing-body">
                {isEditingRec ? (
                  <textarea
                    className="sdi-briefing-textarea"
                    rows={6}
                    value={draftMetadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities)}
                    onChange={(e) => setDraftMetadata({ ...draftMetadata, recommendation: e.target.value })}
                  />
                ) : (
                  <p className="sdi-briefing-text">
                    {metadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities)}
                  </p>
                )}
              </div>
              <div className="sdi-briefing-footer">
                <div className="sdi-briefing-meta">
                  {metadata.recommendationUpdatedAt
                    ? `UPDATED · ${new Date(metadata.recommendationUpdatedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }).toUpperCase()}`
                    : 'DRAFT · NOT YET SAVED'}
                </div>
                <div className="sdi-briefing-actions">
                  {isEditingRec ? (
                    <>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={generateRecommendationMutation.isPending}
                        title="Generate AI recommendation"
                        onClick={() => generateRecommendationMutation.mutate()}
                      >
                        {generateRecommendationMutation.isPending ? 'Generating...' : 'AI Recommendation'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => {
                          setIsEditingRec(false);
                          setDraftMetadata({ ...draftMetadata, recommendation: metadata.recommendation });
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={saveMetadataMutation.isPending}
                        onClick={() => {
                          const next = { ...draftMetadata, recommendationUpdatedAt: new Date().toISOString() };
                          setMetadata(next);
                          setIsEditingRec(false);
                          saveMetadataMutation.mutate(next);
                        }}
                      >
                        {saveMetadataMutation.isPending ? 'Saving...' : 'Save'}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => {
                        if (!draftMetadata.recommendation) {
                          setDraftMetadata({ ...draftMetadata, recommendation: metadata.recommendation || buildFallbackRecommendation(detail, vulnerabilities) });
                        }
                        setIsEditingRec(true);
                      }}
                    >
                      Edit
                    </button>
                  )}
                </div>
              </div>
            </div>
            {findingMessage ? (
              <div className={`sdi-activity-log${findingMessage.startsWith('Failed') ? ' sdi-activity-log--error' : ' sdi-activity-log--ok'}`}>
                {findingMessage}
              </div>
            ) : null}
          </Panel>

          <Panel title="Ownership and Publisher">
            <div className="fd3-kv-table">
              <KVRow label="Vendor / Publisher">
                <input className="sdi-table-input" value={draftVendor} onChange={(e) => setDraftVendor(e.target.value)} placeholder="Vendor or publisher name" />
              </KVRow>
              <KVRow label="Owner">
                <input className="sdi-table-input" value={draftMetadata.owner} onChange={(e) => setDraftMetadata({ ...draftMetadata, owner: e.target.value })} placeholder="Application owner or team" />
              </KVRow>
              <KVRow label="Support Group">
                <input className="sdi-table-input" value={draftMetadata.supportGroup} onChange={(e) => setDraftMetadata({ ...draftMetadata, supportGroup: e.target.value })} placeholder="Support / resolver group" />
              </KVRow>
              <KVRow label="Licensed">
                <select className="sdi-table-input" value={draftMetadata.licensed} onChange={(e) => setDraftMetadata({ ...draftMetadata, licensed: e.target.value })}>
                  <option value="Unknown">Unknown</option>
                  <option value="Licensed">Licensed</option>
                  <option value="Unlicensed">Unlicensed</option>
                  <option value="Open source">Open source</option>
                </select>
              </KVRow>
              <KVRow label="License Type">
                <input className="sdi-table-input" value={draftMetadata.licenseType} onChange={(e) => setDraftMetadata({ ...draftMetadata, licenseType: e.target.value })} placeholder="Commercial, GPL, MIT..." />
              </KVRow>
            </div>
            <div className="button-row" style={{ marginTop: '0.75rem' }}>
              <button
                type="button"
                className="btn btn-primary sdi-save-btn"
                onClick={() => saveMetadataMutation.mutate(draftMetadata)}
              >
                {saveMetadataMutation.isPending ? 'Saving...' : 'Save'}
              </button>
            </div>
          </Panel>

          {bomEvidence.documentCount > 0 && (
            <Panel title="BOM Evidence">
              <div className="fd3-kv-table">
                <KVRow label="Documents">{bomEvidence.documentCount.toLocaleString()}</KVRow>
                <KVRow label="Matched Components">{bomEvidence.componentCount.toLocaleString()}</KVRow>
                <KVRow label="Vulnerability Links">
                  <span className={bomEvidence.vulnerabilityLinkCount > 0 ? 'text-critical' : undefined}>{bomEvidence.vulnerabilityLinkCount.toLocaleString()}</span>
                </KVRow>
                <KVRow label="Active Workflows">
                  <span className={bomEvidence.componentsInWorkflow > 0 ? 'text-warning' : undefined}>{bomEvidence.componentsInWorkflow.toLocaleString()}</span>
                </KVRow>
              </div>
              {(bomEvidence.documents.length > 0 || bomEvidence.components.length > 0) && (
                <div style={{ display: 'grid', gap: '0.75rem', marginTop: '0.75rem' }}>
                  {bomEvidence.documents.length > 0 && (
                    <div>
                      <div className="panel-label">Latest BOM Documents</div>
                      <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.5rem' }}>
                        {bomEvidence.documents.slice(0, 3).map((document) => (
                          <div key={document.bomId} style={{ display: 'grid', gap: '0.15rem' }}>
                            <strong>{document.documentName || document.sourceLabel || document.sourceReference || document.bomId.slice(0, 8)}</strong>
                            <span className="panel-caption">
                              {formatBomLabel(document.specFamily)} · {formatBomLabel(document.documentFormat)} · {formatBomLabel(document.sourceSystem || document.sourceType)} · {document.componentCount.toLocaleString()} components · {formatDateTime(document.ingestedAt)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {bomEvidence.components.length > 0 && (
                    <div>
                      <div className="panel-label">Matched BOM Components</div>
                      <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.5rem' }}>
                        {bomEvidence.components.slice(0, 5).map((component) => (
                          <div key={component.componentId} style={{ display: 'grid', gap: '0.15rem' }}>
                            <strong>{component.name}{component.version ? ` ${component.version}` : ''}</strong>
                            <span className="panel-caption">
                              {component.vulnerabilityCount.toLocaleString()} vuln links · {component.evidenceCount.toLocaleString()} evidence rows · {formatBomLabel(component.workflowStatus)}{component.sourceSystem ? ` · ${formatBomLabel(component.sourceSystem)}` : ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>

      {showFindingConfig ? (
        <div className="modal-overlay" onClick={() => setShowFindingConfig(false)}>
          <div className="modal-panel" onClick={(event) => event.stopPropagation()}>
            <div className="panel-header">
              <div>
                <h3>Finding Configuration</h3>
                <p className="panel-caption">Configure due date, tags, assignment logic, CVEs, and ticket creation for selected impacted assets.</p>
              </div>
              <button type="button" className="modal-close-btn" onClick={() => setShowFindingConfig(false)} aria-label="Close">×</button>
            </div>
            <div className="form-grid">
              <label className="form-field">
                <span>Finding title</span>
                <input value={`${detail.displayName} remediation`} readOnly />
              </label>
              <label className="form-field">
                <span>Priority</span>
                <select value={findingPriority} onChange={(event) => setFindingPriority(event.target.value)}>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </label>
              <label className="form-field">
                <span>Due date</span>
                <input type="date" value={findingDueDate} onChange={(event) => setFindingDueDate(event.target.value)} />
              </label>
              <label className="form-field">
                <span>Tags</span>
                <input value={findingTags} onChange={(event) => setFindingTags(event.target.value)} placeholder="e.g. internet-facing, patching" />
              </label>
              <label className="form-field form-field-wide">
                <span>Assignment / ownership logic</span>
                <select value={findingAssignment} onChange={(event) => setFindingAssignment(event.target.value)}>
                  <option>Assign to lead analyst</option>
                  <option>Assign to software owner</option>
                  <option>Assign to support group</option>
                  <option>Leave unassigned</option>
                </select>
              </label>
              <label className="software-detail-inline-checkbox">
                <input type="checkbox" checked={createServiceNowTickets} onChange={(event) => setCreateServiceNowTickets(event.target.checked)} />
                <span>Create tickets in ServiceNow</span>
              </label>
              <label className="form-field form-field-wide">
                <span>CVEs <em className="panel-caption" style={{ fontStyle: 'normal' }}>(applicable only — all selected by default)</em></span>
                <div className="software-detail-selection-list software-detail-selection-list-modal">
                  {vulnerabilities.length === 0 ? (
                    <p className="panel-caption" style={{ padding: '8px' }}>No applicable CVEs found for this software.</p>
                  ) : vulnerabilities.map((item) => (
                    <label key={item.externalId} className="software-detail-checkbox-row">
                      <input type="checkbox" checked={selectedCves.has(item.externalId)} onChange={() => toggleCve(item.externalId)} />
                      <span className="mono">{item.externalId}</span>
                      <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span>
                    </label>
                  ))}
                </div>
              </label>
              <label className="form-field form-field-wide">
                <span>Recommendation</span>
                <textarea
                  rows={4}
                  value={modalRecommendation}
                  onChange={(event) => setModalRecommendation(event.target.value)}
                  placeholder="Remediation recommendation for this finding..."
                />
              </label>
              <label className="form-field form-field-wide">
                <span>Notes</span>
                <textarea rows={3} value={findingNotes} onChange={(event) => setFindingNotes(event.target.value)} placeholder="Describe remediation approach or ticket creation context..." />
              </label>
            </div>
            <div className="button-row">
              <button type="button" className="btn btn-secondary" onClick={() => setShowFindingConfig(false)}>Close</button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={createFindingsMutation.isPending || selectedCves.size === 0 || selectedComponentIds.size === 0}
                onClick={() => createFindingsMutation.mutate()}
              >
                {createFindingsMutation.isPending ? 'Creating...' : `Create Findings (${selectedComponentIds.size * selectedCves.size})`}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}


function KVRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{label}</span>
      <span className="fd3-kv-val">{children ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fd3-panel">
      <div className="fd3-panel-title">{title}</div>
      <div className="fd3-panel-body">{children}</div>
    </div>
  );
}

function TableOrEmpty({ rows, columns, storageKey, empty }: { rows: DataTableRow[]; columns: DataTableColumn[]; storageKey: string; empty: string }) {
  if (rows.length === 0) {
    return <div className="empty-state"><p>{empty}</p></div>;
  }
  return (
    <div className="inventory-table-shell">
      <DataTable storageKey={storageKey} columns={columns} rows={rows} />
    </div>
  );
}

function isCriticalAsset(asset: SoftwareIdentityAsset): boolean {
  const searchable = `${asset.assetName} ${asset.assetIdentifier} ${asset.assetType}`.toLowerCase();
  return /\b(critical|prod|production|domain controller|dc-|database|payment|internet|external)\b/.test(searchable);
}

function SoftwareFixRecordsTable({ fixes }: { fixes: FixRecord[] }) {
  const [openId, setOpenId] = React.useState<string | null>(null);

  function fixTypeColor(ft: string): { bg: string; color: string; border: string } {
    if (ft === 'UPGRADE' || ft === 'PATCH') return { bg: 'rgba(34,197,94,0.12)', color: '#16a34a', border: 'rgba(34,197,94,0.25)' };
    if (ft === 'NO_FIX') return { bg: 'rgba(239,68,68,0.12)', color: '#dc2626', border: 'rgba(239,68,68,0.25)' };
    return { bg: 'rgba(59,130,246,0.12)', color: '#2563eb', border: 'rgba(59,130,246,0.25)' };
  }

  function parseRich(fix: FixRecord): Record<string, unknown> | null {
    if (!fix.description) return null;
    try {
      const parsed = JSON.parse(fix.description) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object' && ('primary_fix' in parsed || 'compensating_controls' in parsed)) return parsed;
    } catch { /* plain text */ }
    return null;
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ background: 'var(--panel-muted)', borderBottom: '1px solid var(--border)' }}>
            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, width: 90 }}>Fix ID</th>
            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, width: 120 }}>CVE</th>
            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, width: 130 }}>Fix Type</th>
            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Summary</th>
            <th style={{ padding: '8px 12px', textAlign: 'center', fontWeight: 600, color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, width: 60 }}>Details</th>
          </tr>
        </thead>
        <tbody>
          {fixes.map((fix, idx) => {
            const { bg, color, border } = fixTypeColor(fix.fixType);
            const shortId = fix.id.slice(0, 8).toUpperCase();
            const isOpen = openId === fix.id;
            const rich = parseRich(fix);
            const isSupersedence = Boolean(rich?.is_supersedence);
            type PrimaryFix = { action?: string; target_version?: string; patch_id?: string; applies_to?: string; reboot_required?: boolean; verification?: string };
            type Control = { control?: string; effort?: string; effectiveness?: string };
            type LifecycleWarning = { product?: string; is_eol?: boolean; upgrade_recommendation?: string };
            return (
              <React.Fragment key={fix.id}>
                <tr style={{ borderBottom: '1px solid var(--border)', background: idx % 2 === 0 ? 'var(--bg)' : 'var(--panel-muted)' }}>
                  <td style={{ padding: '10px 12px', color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>{shortId}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', color: 'var(--text)' }}>{fix.cveId}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 3, alignItems: 'flex-start' }}>
                      <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: bg, color, border: `1px solid ${border}` }}>
                        {fix.fixType.replace(/_/g, ' ')}
                      </span>
                      {isSupersedence && (
                        <span style={{ fontSize: 10, fontWeight: 600, padding: '1px 5px', borderRadius: 3, background: 'rgba(139,92,246,0.1)', color: '#7c3aed', border: '1px solid rgba(139,92,246,0.25)' }}>
                          ⇑ supersedes
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', maxWidth: 380 }}>
                    <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={fix.summary}>{fix.summary}</span>
                    {fix.osHint && <span style={{ fontSize: 10, color: 'var(--muted)' }}>{fix.osHint}</span>}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center' }}>
                    <button
                      type="button"
                      title="View details"
                      onClick={() => setOpenId(isOpen ? null : fix.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4, borderRadius: 4, color: isOpen ? 'var(--accent)' : 'var(--muted)', fontSize: 16, lineHeight: 1 }}
                    >ℹ</button>
                  </td>
                </tr>
                {isOpen && (
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <td colSpan={5} style={{ padding: '12px 16px', background: 'color-mix(in srgb, var(--accent) 4%, var(--bg))' }}>
                      {rich ? (() => {
                        const pf = rich.primary_fix as PrimaryFix | undefined;
                        const controls = rich.compensating_controls as Control[] | undefined;
                        const rollback = rich.rollback_plan as string[] | undefined;
                        const lifecycle = rich.lifecycle_warning as LifecycleWarning | null | undefined;
                        const supersedes = Array.isArray(rich.supersedes) ? (rich.supersedes as string[]) : [];
                        return (
                          <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>
                            {isSupersedence && supersedes.length > 0 && (
                              <div style={{ marginBottom: 10, padding: '6px 8px', background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.3)', borderRadius: 4 }}>
                                <span style={{ color: '#7c3aed', fontWeight: 700, fontSize: 11 }}>⇑ Supersedence fix </span>
                                <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>— covers older versions: </span>
                                <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: 11 }}>{supersedes.join(', ')}</span>
                              </div>
                            )}
                            {pf && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: 1, marginBottom: 4 }}>Primary Fix</div>
                                <div style={{ fontWeight: 600, marginBottom: 4 }}>{pf.action ?? fix.fixType}</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px 12px', color: 'var(--text-secondary)', fontSize: 11 }}>
                                  {pf.target_version && <span>Target: <strong style={{ color: 'var(--text)' }}>{pf.target_version}</strong></span>}
                                  {pf.patch_id && <span>Patch: <strong style={{ color: 'var(--text)' }}>{pf.patch_id}</strong></span>}
                                  {pf.applies_to && <span>{pf.applies_to}</span>}
                                  <span>Reboot: <strong style={{ color: pf.reboot_required ? '#d97706' : '#16a34a' }}>{pf.reboot_required ? 'Required' : 'Not required'}</strong></span>
                                </div>
                                {pf.verification && (
                                  <div style={{ marginTop: 6, fontSize: 11 }}>
                                    <span style={{ color: '#16a34a', fontWeight: 700 }}>✓ Verify </span>
                                    <span style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>{pf.verification}</span>
                                  </div>
                                )}
                              </div>
                            )}
                            {controls && controls.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: 1, marginBottom: 4 }}>Compensating Controls</div>
                                {controls.map((c, i) => (
                                  <div key={i} style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 2 }}>
                                    {c.control} — Effort: {c.effort}, Effectiveness: {c.effectiveness}
                                  </div>
                                ))}
                              </div>
                            )}
                            {rollback && rollback.length > 0 && (
                              <div style={{ marginBottom: 8 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: 1, marginBottom: 4 }}>Rollback Plan</div>
                                <ol style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: 'var(--text-secondary)' }}>
                                  {rollback.map((s, i) => <li key={i}>{s}</li>)}
                                </ol>
                              </div>
                            )}
                            {lifecycle?.is_eol && (
                              <div style={{ padding: '6px 8px', background: 'rgba(217,119,6,0.08)', border: '1px solid rgba(217,119,6,0.3)', borderRadius: 4, fontSize: 11 }}>
                                <span style={{ color: '#d97706' }}>⚠ EOL — {lifecycle.product}</span>
                                {lifecycle.upgrade_recommendation && <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>{lifecycle.upgrade_recommendation}</div>}
                              </div>
                            )}
                            {fix.sourceUrls && fix.sourceUrls.length > 0 && (
                              <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                {fix.sourceUrls.slice(0, 2).map(url => (
                                  <a key={url} href={url} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: 'var(--accent)', textDecoration: 'underline', wordBreak: 'break-all' }}>
                                    {url.length > 50 ? url.slice(0, 47) + '…' : url}
                                  </a>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })() : (
                        <p style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', margin: 0 }}>{fix.description ?? 'No description available.'}</p>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
