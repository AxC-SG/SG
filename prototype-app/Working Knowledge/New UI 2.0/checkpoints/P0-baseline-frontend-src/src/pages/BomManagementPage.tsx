import React from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type BomFetchPayload, type BomIngestionResult, type BomSource, type BomType, type CbomComponent, type CbomRiskFinding, type IngestionJob } from '../api/client';
import { useGithubSbomSourcesQuery, useSyncRunsQuery } from '../features/connect/queries';
import type { GithubSbomSource, SyncRun } from '../features/connect/types';
import { FindingSeverityChips } from '../features/findings/components/FindingSeverityChips';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';

// ── Constants ──────────────────────────────────────────────────────────────

type AssetType = 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
type ManualMode = 'file' | 'url';

const BOM_META: Record<BomType, { label: string; short: string; description: string; icon: string }> = {
  SBOM:   { label: 'SBOM',       short: 'SBOM',    description: 'Software Bill of Materials (CycloneDX / SPDX)', icon: '📦' },
  AI_BOM: { label: 'AI BOM',     short: 'AI BOM',  description: 'AI/ML model bill of materials (CycloneDX 1.5+)', icon: '🤖' },
  CBOM:   { label: 'CBOM',       short: 'CBOM',    description: 'Cryptography bill of materials',                icon: '🔐' },
  VENDOR: { label: 'Vendor BOM', short: 'Vendor',  description: 'Vendor-supplied BOM for third-party products',  icon: '🏭' },
};

const BOM_TYPES: BomType[] = ['SBOM', 'CBOM', 'AI_BOM', 'VENDOR'];

type GithubSourceOption = { value: string; label: string; needsRepo: boolean; hint?: string };

const GITHUB_SOURCE_OPTIONS: Record<BomType, GithubSourceOption[]> = {
  SBOM:   [
    { value: 'dependency-graph/sbom', label: 'GitHub Dep Graph SBOM', needsRepo: false },
    { value: 'ghcr/attestations',     label: 'GHCR Image SBOM (all images)', needsRepo: false },
  ],
  CBOM:   [{ value: 'repository/cbom',  label: 'Repository CBOM file scan', needsRepo: true, hint: 'Scans for *.cbom.json / *.cbom.xml' }],
  AI_BOM: [{ value: 'repository/aibom', label: 'Repository AIBOM file scan', needsRepo: true, hint: 'Scans for *.aibom.json / *.ai-bom.json / *.ml-bom.json' }],
  VENDOR: [],
};

// ── BOM metadata extraction ────────────────────────────────────────────────

type ExtractedMeta = { assetType?: AssetType; assetName?: string; assetIdentifier?: string; supplier?: string };

function mapCycloneDxType(type: string): AssetType {
  const t = (type ?? '').toLowerCase();
  if (t === 'container') return 'CONTAINER_IMAGE';
  if (t === 'device' || t === 'firmware') return 'HOST';
  return 'APPLICATION';
}

function extractCycloneDxMeta(root: Record<string, unknown>): ExtractedMeta {
  const meta = root['metadata'] as Record<string, unknown> | undefined;
  const comp = meta?.['component'] as Record<string, unknown> | undefined;
  const supplierNode = (meta?.['supplier'] ?? meta?.['manufacturer']) as Record<string, unknown> | undefined;
  const name = comp?.['name'] as string | undefined;
  const purl = comp?.['purl'] as string | undefined;
  const version = comp?.['version'] as string | undefined;
  const type = comp?.['type'] as string | undefined;
  const identifier = purl || (name && version ? `pkg:generic/${name}@${version}` : name) || '';
  return { assetType: type ? mapCycloneDxType(type) : 'APPLICATION', assetName: name, assetIdentifier: identifier || undefined, supplier: (supplierNode?.['name'] as string) || undefined };
}

function extractSpdxMeta(root: Record<string, unknown>): ExtractedMeta {
  const docName = root['name'] as string | undefined;
  const ns = root['documentNamespace'] as string | undefined;
  const packages = root['packages'] as Array<Record<string, unknown>> | undefined;
  const primary = packages?.find(p => p['SPDXID'] === 'SPDXRef-Package' || p['SPDXID'] === 'SPDXRef-RootPackage') ?? packages?.[0];
  const name = (primary?.['name'] as string) || docName;
  const version = primary?.['versionInfo'] as string | undefined;
  const refs = primary?.['externalRefs'] as Array<Record<string, unknown>> | undefined;
  const purlRef = refs?.find(r => (r['referenceType'] as string)?.toLowerCase() === 'purl');
  const purl = purlRef?.['referenceLocator'] as string | undefined;
  const identifier = purl || ns || (name && version ? `pkg:generic/${name}@${version}` : undefined);
  const rawSupplier = primary?.['supplier'] as string | undefined;
  const supplier = rawSupplier && rawSupplier !== 'NOASSERTION' ? rawSupplier.replace(/^Organization:\s*/i, '').replace(/^Person:\s*/i, '').trim() || undefined : undefined;
  return { assetType: 'APPLICATION', assetName: name, assetIdentifier: identifier, supplier };
}

function firstElement(parent: Element | Document | undefined, localName: string): Element | undefined {
  if (!parent) return undefined;
  return Array.from(parent.children).find((child) => child.localName === localName);
}

function firstText(parent: Element | Document | undefined, localName: string): string | undefined {
  if (!parent) return undefined;
  const value = firstElement(parent, localName)?.textContent?.trim();
  return value || undefined;
}

function extractCycloneDxXmlMeta(doc: Document): ExtractedMeta | null {
  const bom = doc.documentElement;
  if (!bom || bom.localName !== 'bom') return null;

  const metadata = firstElement(bom, 'metadata');
  const component = metadata ? firstElement(metadata, 'component') : undefined;
  if (!component) return null;

  const supplierNode = firstElement(metadata, 'supplier')
    ?? firstElement(metadata, 'manufacturer')
    ?? firstElement(component, 'supplier');
  const name = firstText(component, 'name');
  const version = firstText(component, 'version');
  const purl = firstText(component, 'purl');
  const bomRef = component.getAttribute('bom-ref')?.trim() || undefined;
  const type = component.getAttribute('type') || undefined;
  const identifier = purl
    || (bomRef?.startsWith('pkg:') ? bomRef : undefined)
    || (name && version ? `pkg:generic/${name}@${version}` : name)
    || '';

  return {
    assetType: type ? mapCycloneDxType(type) : 'APPLICATION',
    assetName: name,
    assetIdentifier: identifier || undefined,
    supplier: firstText(supplierNode, 'name'),
  };
}

function parseBomMeta(text: string): ExtractedMeta | null {
  try {
    const root = JSON.parse(text) as Record<string, unknown>;
    const unwrapped = (root['sbom'] as Record<string, unknown>) ?? root;
    if (unwrapped['bomFormat'] || unwrapped['components'] || unwrapped['metadata']) return extractCycloneDxMeta(unwrapped);
    if (unwrapped['spdxVersion'] || unwrapped['packages']) return extractSpdxMeta(unwrapped);
  } catch { /* fall through */ }

  try {
    if (typeof DOMParser === 'undefined') return null;
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length > 0) return null;
    return extractCycloneDxXmlMeta(doc);
  } catch { /* fall through */ }

  return null;
}

// ── Pipeline helpers ───────────────────────────────────────────────────────

function pipelineStatusMeta(status?: string | null): { cls: string; label: string } {
  if (!status) return { cls: 'pipeline-dot--none', label: 'Never run' };
  if (status === 'SUCCESS') return { cls: 'pipeline-dot--success', label: 'Success' };
  if (status === 'FAILURE') return { cls: 'pipeline-dot--failure', label: 'Failed' };
  return { cls: 'pipeline-dot--active', label: status };
}

function sourceTypeLabel(path?: string | null): string {
  if (path === 'ghcr/attestations') return 'GHCR Image SBOM';
  if (path === 'repository/cbom') return 'Repo CBOM';
  if (path === 'repository/aibom') return 'Repo AIBOM';
  return 'Dep Graph SBOM';
}

function isSyncRunTerminal(run?: SyncRun | null): boolean {
  if (!run) return false;
  const v = run.status.trim().toUpperCase();
  return v === 'COMPLETED' || v === 'PARTIAL_SUCCESS' || v === 'FAILED';
}

function formatScore(score?: number | null): string {
  return score == null ? '0.00' : score.toFixed(2);
}

function displayValue(value?: string | number | null): string {
  if (value == null || value === '') return '—';
  return String(value);
}

function severityClass(severity?: string | null): string {
  const value = (severity ?? '').toLowerCase();
  if (value === 'critical') return 'status-badge--critical';
  if (value === 'high') return 'status-badge--high';
  if (value === 'medium') return 'status-badge--medium';
  if (value === 'low') return 'status-badge--low';
  return 'status-badge--info';
}

// ── Component ──────────────────────────────────────────────────────────────

type Props = {
  title?: string;
  caption?: string;
  includeGithubSources?: boolean;
};

export function BomManagementPage({
  title = 'BOM Management',
  caption = 'Unified ingestion for SBOM, CBOM, AI BOM, and Vendor BOM — file upload, URL fetch, or automated GitHub pipeline.',
  includeGithubSources = true,
}: Props) {
  const queryClient = useQueryClient();

  // ── BOM type ──
  const [bomType, setBomType] = React.useState<BomType>('SBOM');

  // ── Manual ingestion ──
  const [manualMode, setManualMode] = React.useState<ManualMode>('file');
  const [assetType, setAssetType] = React.useState<AssetType>('APPLICATION');
  const [assetName, setAssetName] = React.useState('');
  const [assetIdentifier, setAssetIdentifier] = React.useState('');
  const [supplier, setSupplier] = React.useState('');
  const [file, setFile] = React.useState<File | null>(null);
  // Naming a source replaces that source's current version. Leaving it blank creates an
  // independent source, so nothing is implicitly replaced.
  const [replaceSourceId, setReplaceSourceId] = React.useState('');
  // Only an asserted complete inventory can later justify retiring a component, so this is
  // off by default and CBOM can never assert it.
  const [assertsCompleteInventory, setAssertsCompleteInventory] = React.useState(false);
  const [existingSources, setExistingSources] = React.useState<BomSource[]>([]);

  const [parseWarning, setParseWarning] = React.useState('');
  const [metaSource, setMetaSource] = React.useState<string | null>(null);
  const [sourceUrl, setSourceUrl] = React.useState('');
  const [showAuthHeader, setShowAuthHeader] = React.useState(false);
  const [authorizationHeader, setAuthorizationHeader] = React.useState('');
  const [urlParsing, setUrlParsing] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [queuedJobId, setQueuedJobId] = React.useState<string | null>(null);
  const [queueMessage, setQueueMessage] = React.useState('');
  const [queueMessageTone, setQueueMessageTone] = React.useState<'info' | 'success' | 'warning'>('info');
  const [ingestError, setIngestError] = React.useState('');
  const [ingestResult, setIngestResult] = React.useState<BomIngestionResult | null>(null);
  React.useEffect(() => {
    let cancelled = false;
    api.listBomSources()
      .then(sources => { if (!cancelled) setExistingSources(sources); })
      // A failure here only costs the replace affordance; uploading a new source still works.
      .catch(() => { if (!cancelled) setExistingSources([]); });
    return () => { cancelled = true; };
  }, [ingestResult]);
  const [selectedCbomAssetId, setSelectedCbomAssetId] = React.useState<string | null>(null);
  const [cbomSeverityFilter, setCbomSeverityFilter] = React.useState('');
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // ── GitHub pipeline ──
  const [ghSourcePath, setGhSourcePath] = React.useState('dependency-graph/sbom');
  const [ghOwner, setGhOwner] = React.useState('');
  const [ghRepo, setGhRepo] = React.useState('');
  const [ghToken, setGhToken] = React.useState('');
  const [ghPipelineName, setGhPipelineName] = React.useState('');
  const [ghFrequency, setGhFrequency] = React.useState<'ONCE' | 'INTERVAL'>('ONCE');
  const [ghIntervalHours, setGhIntervalHours] = React.useState('24');
  const [ghEnabled, setGhEnabled] = React.useState(true);
  const [pipelineBusy, setPipelineBusy] = React.useState<string | null>(null);
  const [pipelineMsg, setPipelineMsg] = React.useState('');
  const [activeRunId, setActiveRunId] = React.useState<string | null>(null);

  const githubSourcesQuery = useGithubSbomSourcesQuery();
  const activeRunsQuery = useSyncRunsQuery(
    { category: 'inventory', limit: 50 },
    activeRunId != null,
    RUN_QUEUE_REFRESH_INTERVAL_MS
  );
  const githubSources = React.useMemo(() => githubSourcesQuery.data ?? [], [githubSourcesQuery.data]);
  const cbomPostureQuery = useQuery({
    queryKey: ['cbom-posture'],
    queryFn: () => api.listCbomPosture(),
    enabled: bomType === 'CBOM',
  });
  const cbomPosture = cbomPostureQuery.data ?? [];
  const activeCbomAssetId = selectedCbomAssetId ?? cbomPosture[0]?.assetId ?? null;
  const cbomComponentsQuery = useQuery({
    queryKey: ['cbom-components', activeCbomAssetId],
    queryFn: () => api.listCbomComponents(activeCbomAssetId!, 0, 100),
    enabled: bomType === 'CBOM' && activeCbomAssetId != null,
  });
  const cbomFindingsQuery = useQuery({
    queryKey: ['cbom-findings', activeCbomAssetId, cbomSeverityFilter],
    queryFn: () => api.listCbomFindings(activeCbomAssetId!, cbomSeverityFilter || undefined),
    enabled: bomType === 'CBOM' && activeCbomAssetId != null,
  });

  React.useEffect(() => {
    if (bomType === 'CBOM' && ingestResult?.assetId) {
      setSelectedCbomAssetId(ingestResult.assetId);
      void queryClient.invalidateQueries({ queryKey: ['cbom-posture'] });
      void queryClient.invalidateQueries({ queryKey: ['cbom-components', ingestResult.assetId] });
      void queryClient.invalidateQueries({ queryKey: ['cbom-findings', ingestResult.assetId] });
    }
  }, [bomType, ingestResult, queryClient]);

  // When BOM type changes, reset GitHub source path to first valid option
  React.useEffect(() => {
    const opts = GITHUB_SOURCE_OPTIONS[bomType];
    if (opts.length > 0 && !opts.find(o => o.value === ghSourcePath)) {
      setGhSourcePath(opts[0].value);
    }
  }, [bomType, ghSourcePath]);

  // Poll active run until terminal
  React.useEffect(() => {
    if (!activeRunId) return;
    const run = (activeRunsQuery.data ?? []).find(r => r.id === activeRunId);
    if (run && isSyncRunTerminal(run)) {
      setActiveRunId(null);
      const s = run.status.toUpperCase();
      setPipelineMsg(s === 'COMPLETED' ? 'Pipeline run completed successfully.' :
        s === 'PARTIAL_SUCCESS' ? `Completed with partial success. ${run.recordsInserted} components ingested.` :
        `Run failed: ${run.errorMessage ?? 'Unknown error'}`);
      void githubSourcesQuery.refetch();
    }
  }, [activeRunId, activeRunsQuery.data, githubSourcesQuery]);

  // ── Job polling for URL fetch ──
  const parseJobResult = React.useCallback((job: IngestionJob): BomIngestionResult | null => {
    if (!job.resultJson) return null;
    try {
      const p = JSON.parse(job.resultJson) as Record<string, unknown>;
      if (typeof p['bomId'] !== 'string' || typeof p['assetId'] !== 'string') return null;
      return {
        bomId: p['bomId'],
        assetId: p['assetId'],
        bomType: typeof p['bomType'] === 'string' ? p['bomType'] : bomType,
        format: typeof p['format'] === 'string' ? p['format'] : 'UNKNOWN',
        formatVersion: typeof p['formatVersion'] === 'string' ? p['formatVersion'] : '',
        specFamily: typeof p['specFamily'] === 'string' ? p['specFamily'] : 'UNKNOWN',
        documentFormat: typeof p['documentFormat'] === 'string' ? p['documentFormat'] : 'UNKNOWN',
        supportLevel: typeof p['supportLevel'] === 'string' ? p['supportLevel'] : 'UNKNOWN',
        supported: typeof p['supported'] === 'boolean' ? p['supported'] : false,
        warnings: Array.isArray(p['warnings']) ? p['warnings'].filter((v): v is string => typeof v === 'string') : [],
        componentCount: typeof p['componentsIngested'] === 'number' ? p['componentsIngested'] : (typeof p['componentCount'] === 'number' ? p['componentCount'] : 0),
        findingsGenerated: typeof p['findingsGenerated'] === 'number' ? p['findingsGenerated'] : 0,
        status: typeof p['status'] === 'string' ? p['status'] : job.status,
        action: typeof p['action'] === 'string' ? p['action'] : 'CREATED',
      };
    } catch { return null; }
  }, [bomType]);

  React.useEffect(() => {
    if (!queuedJobId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const job = await api.getIngestionJob(queuedJobId);
        if (cancelled) return;
        if (job.status === 'SUCCEEDED') {
          const parsed = parseJobResult(job);
          setIngestResult(parsed);
          setQueueMessageTone('success');
          setQueueMessage(parsed ? 'BOM fetch completed successfully. Results are now available below.' : 'BOM fetch completed, but the result payload could not be read.');
          setQueuedJobId(null);
        } else if (job.status === 'FAILED' || job.status === 'CANCELLED') {
          setIngestError(job.failureMessage || 'BOM fetch failed.');
          setQueuedJobId(null);
        } else {
          setQueueMessageTone('info');
          setQueueMessage(job.status === 'RUNNING'
            ? `BOM fetch is running for job ${queuedJobId}.`
            : `BOM fetch is queued for job ${queuedJobId}.`);
          window.setTimeout(() => void poll(), 1500);
        }
      } catch (err) {
        if (!cancelled) { setIngestError(err instanceof Error ? err.message : 'Failed to check job status.'); setQueuedJobId(null); }
      }
    };
    void poll();
    return () => { cancelled = true; };
  }, [parseJobResult, queuedJobId]);

  // ── Manual ingestion handlers ──
  function applyMeta(meta: ExtractedMeta, src: string) {
    if (meta.assetType) setAssetType(meta.assetType);
    if (meta.assetName) setAssetName(meta.assetName);
    if (meta.assetIdentifier) setAssetIdentifier(meta.assetIdentifier);
    if (meta.supplier) setSupplier(meta.supplier);
    setMetaSource(src);
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null;
    setFile(f);
    setIngestError(''); setIngestResult(null); setQueuedJobId(null); setQueueMessage('');
    setMetaSource(null); setParseWarning('');
    if (!f) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const text = ev.target?.result as string;
      const meta = parseBomMeta(text);
      if (meta && (meta.assetName || meta.assetIdentifier)) applyMeta(meta, f.name);
      else if (f.name.endsWith('.json') || f.name.endsWith('.xml')) setParseWarning('Metadata not extracted — fill in the fields manually.');
    };
    reader.readAsText(f);
  }

  async function handleUrlPreview() {
    const url = sourceUrl.trim();
    if (!url) return;
    setUrlParsing(true); setMetaSource(null); setParseWarning('');
    try {
      const headers: Record<string, string> = {};
      if (showAuthHeader && authorizationHeader.trim()) headers['Authorization'] = authorizationHeader.trim();
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const meta = parseBomMeta(await res.text());
      if (meta && (meta.assetName || meta.assetIdentifier)) applyMeta(meta, url);
      else setParseWarning('URL fetched but no recognisable BOM metadata found — fill in fields manually.');
    } catch {
      setParseWarning('Could not fetch URL for metadata preview (possible CORS restriction).');
    } finally { setUrlParsing(false); }
  }

  async function submitManual() {
    if (!assetName.trim()) { setIngestError('Asset Name is required'); return; }
    if (!assetIdentifier.trim()) { setIngestError('Asset Identifier is required'); return; }
    if (manualMode === 'url' && !sourceUrl.trim()) { setIngestError('Source URL is required'); return; }
    if (manualMode === 'file' && !file) { setIngestError('Please select a BOM file'); return; }
    setIngestError(''); setIngestResult(null); setQueuedJobId(null); setQueueMessage(''); setQueueMessageTone('info'); setLoading(true);
    try {
      if (manualMode === 'url') {
        const payload: BomFetchPayload = {
          bomType, assetType, assetName: assetName.trim(), assetIdentifier: assetIdentifier.trim(),
          sourceUrl: sourceUrl.trim(), supplier: supplier.trim() || undefined,
          authorizationHeader: showAuthHeader && authorizationHeader.trim() ? authorizationHeader.trim() : undefined,
        };
        const accepted = await api.bomFetch(payload);
        setQueuedJobId(accepted.jobId);
        setQueueMessageTone('info');
        setQueueMessage(
          accepted.existingJob
            ? `Using existing ingestion job ${accepted.jobId}. This page will update automatically when it finishes.`
            : `Queued ingestion job ${accepted.jobId}. This page will update automatically when processing starts and completes.`
        );
      } else {
        const fd = new FormData();
        fd.append('file', file!); fd.append('bomType', bomType); fd.append('assetType', assetType);
        fd.append('assetName', assetName.trim()); fd.append('assetIdentifier', assetIdentifier.trim());
        if (supplier.trim()) fd.append('supplier', supplier.trim());
        if (replaceSourceId) fd.append('sourceId', replaceSourceId);
        // A CBOM describes cryptographic assets and can never speak for an asset's whole
        // software inventory; the server rejects the combination too.
        if (assertsCompleteInventory && bomType !== 'CBOM') {
          fd.append('completeness', 'COMPLETE_ASSET_SOFTWARE');
        }
        setIngestResult(await api.bomUpload(fd));
      }
    } catch (err) {
      setIngestError(err instanceof Error ? err.message : 'Ingestion failed');
    } finally { setLoading(false); }
  }

  // ── GitHub pipeline handlers ──
  const currentSourceOpts = GITHUB_SOURCE_OPTIONS[bomType];
  const currentSourceOpt = currentSourceOpts.find(o => o.value === ghSourcePath) ?? currentSourceOpts[0];
  const needsRepo = currentSourceOpt?.needsRepo ?? false;

  async function runPipelineOnce() {
    if (!ghOwner.trim()) { setPipelineMsg('GitHub owner is required'); return; }
    if (needsRepo && !ghRepo.trim()) { setPipelineMsg('GitHub repository is required for this source type'); return; }
    if (ghSourcePath === 'dependency-graph/sbom' && !ghRepo.trim()) {
      if (!window.confirm(`Repository is empty. This will scan all repos under "${ghOwner.trim()}". Continue?`)) return;
    }
    setPipelineMsg(''); setPipelineBusy('run');
    try {
      const isGhcr = ghSourcePath === 'ghcr/attestations';
      const run = isGhcr
        ? await api.queueGithubGhcrRun(ghOwner.trim())
        : await api.queueGithubRepositoryRun({ owner: ghOwner.trim(), repo: ghRepo.trim() || undefined, includeAllRepos: !ghRepo.trim(), path: isGhcr ? undefined : ghSourcePath });
      setActiveRunId(run.runId);
      setPipelineMsg(`Run queued (${run.runId}). Tracking status…`);
      await activeRunsQuery.refetch();
    } catch (e) {
      setPipelineMsg(e instanceof Error ? e.message : 'Failed to queue run');
    } finally { setPipelineBusy(null); }
  }

  async function savePipeline() {
    if (!ghPipelineName.trim()) { setPipelineMsg('Pipeline name is required'); return; }
    if (!ghOwner.trim()) { setPipelineMsg('GitHub owner is required'); return; }
    if ((needsRepo || ghSourcePath === 'dependency-graph/sbom') && !ghRepo.trim()) { setPipelineMsg('GitHub repository is required for this source type'); return; }
    setPipelineMsg(''); setPipelineBusy('save');
    try {
      await api.createGithubSbomSource({
        name: ghPipelineName.trim(), owner: ghOwner.trim(),
        repo: ghSourcePath !== 'ghcr/attestations' ? ghRepo.trim() : '',
        path: ghSourcePath, frequency: ghFrequency,
        intervalMinutes: ghFrequency === 'INTERVAL' ? Math.max(5, (Number(ghIntervalHours) || 24) * 60) : undefined,
        enabled: ghEnabled, githubToken: ghToken.trim() || undefined,
      });
      setPipelineMsg('Pipeline saved.');
      await queryClient.invalidateQueries({ queryKey: ['github-sbom-sources'] });
      await githubSourcesQuery.refetch();
      setGhPipelineName('');
    } catch (e) {
      setPipelineMsg(e instanceof Error ? e.message : 'Failed to save pipeline');
    } finally { setPipelineBusy(null); }
  }

  async function runSavedPipeline(id: string) {
    setPipelineBusy(id); setPipelineMsg('');
    try {
      const run = await api.runGithubSbomSource(id);
      setActiveRunId(run.runId);
      setPipelineMsg(`Run queued (${run.runId}). Tracking status…`);
      await activeRunsQuery.refetch();
    } catch (e) {
      setPipelineMsg(e instanceof Error ? e.message : 'Failed to run pipeline');
    } finally { setPipelineBusy(null); }
  }

  async function deleteSavedPipeline(id: string, name: string) {
    if (!window.confirm(`Delete pipeline "${name}"?`)) return;
    setPipelineBusy(`del:${id}`); setPipelineMsg('');
    try {
      await api.deleteGithubSbomSource(id);
      setPipelineMsg(`Deleted "${name}".`);
      await queryClient.invalidateQueries({ queryKey: ['github-sbom-sources'] });
      await githubSourcesQuery.refetch();
    } catch (e) {
      setPipelineMsg(e instanceof Error ? e.message : 'Failed to delete pipeline');
    } finally { setPipelineBusy(null); }
  }

  async function acceptCbomFinding(finding: CbomRiskFinding) {
    await api.acceptCbomFinding(finding.id);
    await queryClient.invalidateQueries({ queryKey: ['cbom-posture'] });
    await queryClient.invalidateQueries({ queryKey: ['cbom-components', finding.assetId] });
    await queryClient.invalidateQueries({ queryKey: ['cbom-findings', finding.assetId] });
  }

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="page-grid" style={{ gap: 16 }}>

      {/* ── BOM Type Selector ── */}
      <section className="panel">
        <div className="panel-header">
          <h3>{title}</h3>
          <span className="panel-caption">{caption}</span>
        </div>

        <div className="ingestion-form">
          <div className="form-section">
            <p className="form-section-title">BOM Type</p>
            <div className="bom-type-cards">
              {BOM_TYPES.map(bt => {
                const m = BOM_META[bt];
                return (
                  <button
                    key={bt}
                    type="button"
                    className={`bom-type-card${bomType === bt ? ' selected' : ''}`}
                    onClick={() => { setBomType(bt); setIngestResult(null); setIngestError(''); }}
                  >
                    <span className="bom-type-icon">{m.icon}</span>
                    <span className="bom-type-name">{m.label}</span>
                    <span className="bom-type-desc">{m.description}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* ── Manual Ingestion ── */}
      <section className="panel">
        <div className="panel-header">
          <h3>Ingest Now</h3>
          <span className="panel-caption">Upload a {BOM_META[bomType].short} file or fetch from a URL.</span>
        </div>

        <div className="ingestion-form">

          {/* Source */}
          <div className="form-section">
            <p className="form-section-title">Source</p>
            <div className="bom-mode-row">
              <div className="ingestion-mode-tabs">
                <button type="button" className={`connect-filter-btn${manualMode === 'file' ? ' active' : ''}`}
                  onClick={() => { setManualMode('file'); setIngestResult(null); setIngestError(''); setMetaSource(null); }}>
                  File Upload
                </button>
                <button type="button" className={`connect-filter-btn${manualMode === 'url' ? ' active' : ''}`}
                  onClick={() => { setManualMode('url'); setIngestResult(null); setIngestError(''); setMetaSource(null); }}>
                  URL Fetch
                </button>
              </div>

              {manualMode === 'file' && (
                <div className="bom-inline-file">
                  <input ref={fileInputRef} type="file" accept=".json,.xml,.spdx,.rdf" style={{ display: 'none' }} onChange={handleFileChange} />
                  <button type="button" className="btn btn-secondary" onClick={() => fileInputRef.current?.click()}>Choose File</button>
                  {file
                    ? <span className="file-upload-name">{file.name} ({(file.size / 1024).toFixed(1)} KB)</span>
                    : <span className="panel-caption">No file chosen — .json, .xml, .spdx, .rdf</span>}
                </div>
              )}

              {manualMode === 'url' && (
                <div className="bom-inline-url">
                  <input type="url" className="form-input" placeholder="https://example.com/bom.json"
                    value={sourceUrl} onChange={e => { setSourceUrl(e.target.value); setMetaSource(null); setIngestResult(null); }} />
                  <button type="button" className="btn btn-secondary" disabled={!sourceUrl.trim() || urlParsing} onClick={() => void handleUrlPreview()}>
                    {urlParsing ? 'Fetching…' : 'Preview'}
                  </button>
                </div>
              )}
            </div>

            {manualMode === 'url' && (
              <div className="form-row" style={{ marginTop: 8 }}>
                <label className="form-checkbox-label">
                  <input type="checkbox" checked={showAuthHeader} onChange={e => setShowAuthHeader(e.target.checked)} />
                  Include Authorization header
                </label>
                {showAuthHeader && (
                  <input type="text" className="form-input" placeholder="Bearer <token>" value={authorizationHeader}
                    onChange={e => setAuthorizationHeader(e.target.value)} style={{ marginTop: 6 }} />
                )}
              </div>
            )}
          </div>

          {/* Asset Context */}
          <div className="form-section">
            <p className="form-section-title">Asset Context</p>
            {metaSource && <div className="notice" style={{ marginBottom: 8 }}>Fields auto-filled from <strong>{metaSource}</strong>. Review before ingesting.</div>}
            {parseWarning && <div className="notice error" style={{ marginBottom: 8 }}>{parseWarning}</div>}

            <div className="form-row-2col">
              <label className="form-label">Asset Name
                <input type="text" className="form-input" placeholder="e.g. payments-api" value={assetName} onChange={e => setAssetName(e.target.value)} />
              </label>
              <label className="form-label">Asset Type
                <select className="form-select" value={assetType} onChange={e => setAssetType(e.target.value as AssetType)}>
                  <option value="APPLICATION">Application</option>
                  <option value="HOST">Host</option>
                  <option value="CONTAINER_IMAGE">Container Image</option>
                </select>
              </label>
            </div>
            <div className="form-row">
              <label className="form-label">Asset Identifier
                <input type="text" className="form-input" placeholder="pkg:npm/my-app@1.0.0 or git repo URL" value={assetIdentifier} onChange={e => setAssetIdentifier(e.target.value)} />
              </label>
            </div>
            <div className="form-row">
              <label className="form-label">Supplier <span style={{ fontWeight: 400, color: 'var(--muted)' }}>(optional)</span>
                <input type="text" className="form-input" placeholder="Acme Corp" value={supplier} onChange={e => setSupplier(e.target.value)} />
              </label>
            </div>
            <div className="form-row">
              <label className="form-label">Replaces existing source <span style={{ fontWeight: 400, color: 'var(--muted)' }}>(optional)</span>
                <select
                  className="form-input"
                  value={replaceSourceId}
                  onChange={e => setReplaceSourceId(e.target.value)}
                >
                  <option value="">Upload as a new, independent source</option>
                  {existingSources
                    .filter(source => source.bomType === bomType)
                    .map(source => (
                      <option key={source.id} value={source.id}>
                        {source.bomType}
                        {source.supplier ? ` · ${source.supplier}` : ''}
                        {` · rev ${source.revision}`}
                        {` · ${source.supportedComponentCount} components`}
                      </option>
                    ))}
                </select>
              </label>
              <div style={{ fontSize: '0.8rem', color: 'var(--muted)', marginTop: 4 }}>
                Leave this alone to add a source. Documents are not replaced just because they
                share an asset and supplier — pick the source you mean to supersede.
              </div>
            </div>
            {bomType !== 'CBOM' && (
              <div className="form-row">
                <label className="form-label" style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontWeight: 500 }}>
                  <input
                    type="checkbox"
                    checked={assertsCompleteInventory}
                    onChange={e => setAssertsCompleteInventory(e.target.checked)}
                    style={{ marginTop: 3 }}
                  />
                  <span>
                    This document lists the asset&rsquo;s complete software inventory
                    <div style={{ fontWeight: 400, fontSize: '0.8rem', color: 'var(--muted)', marginTop: 2 }}>
                      Recorded as an audited assertion against your user. Only a complete
                      document lets a later replacement retire the components it omits; a
                      partial one just stops vouching for them. Asserting this wrongly can
                      retire software that is still installed.
                    </div>
                  </span>
                </label>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="form-actions-bar">
            <button type="button" className="btn btn-primary"
              disabled={loading || (manualMode === 'file' ? !file : !sourceUrl.trim())}
              onClick={() => void submitManual()}>
              {loading ? 'Submitting…' : `Ingest ${BOM_META[bomType].short}`}
            </button>
            {ingestError && <p className="form-error" style={{ margin: 0 }}>{ingestError}</p>}
          </div>

          {queueMessage && (
            <div className={`notice${queueMessageTone === 'success' ? ' success' : queueMessageTone === 'warning' ? ' warning' : ''}`} role="status">
              {queueMessage}
            </div>
          )}

          {ingestResult && (
            <div className="ingestion-result ingestion-result--success">
              <div className="ingestion-result-metrics">
                <div className="result-metric"><span className="result-metric-value">{ingestResult.componentCount}</span><span className="result-metric-label">Components ingested</span></div>
                {ingestResult.bomType === 'CBOM' && <div className="result-metric"><span className="result-metric-value">{ingestResult.findingsGenerated}</span><span className="result-metric-label">Findings generated</span></div>}
              </div>
              {ingestResult.bomType !== 'CBOM' && (
                <p className="panel-caption" style={{ margin: '8px 0' }}>
                  Ingestion completed. Software vulnerability assessment, correlation, and finding creation run asynchronously after ingestion. Check BOM Inventory for component links and Findings for confirmed vulnerabilities.
                  {ingestResult.bomType === 'AI_BOM' && ' AI-resource dependency linking runs later as shared software findings become available. An empty findings list does not confirm a clean assessment. AI Grid posture findings require an AI policy assessment; uploading an AI BOM alone does not create them.'}
                </p>
              )}
              <div className="result-meta">
                <span>{ingestResult.action} · {ingestResult.bomType} · {ingestResult.format} {ingestResult.formatVersion}</span>
                <span>{ingestResult.specFamily} · {ingestResult.documentFormat} · {ingestResult.supportLevel}</span>
                <span>BOM ID: <code>{ingestResult.bomId}</code></span>
              </div>
              {ingestResult.warnings.map(w => <div key={w} className="notice error" style={{ marginTop: 8 }}>{w}</div>)}
            </div>
          )}
        </div>
      </section>

      {bomType === 'CBOM' && (
        <section className="panel">
          <div className="panel-header">
            <h3>Crypto Posture</h3>
            <span className="panel-caption">Cryptographic assets and CBOM risk findings are tracked separately from software inventory.</span>
          </div>

          {cbomPostureQuery.isLoading ? (
            <p className="panel-caption" style={{ padding: '0 16px 16px' }}>Loading CBOM posture…</p>
          ) : cbomPosture.length === 0 ? (
            <div className="empty-state" style={{ padding: '16px 16px 24px' }}>
              <p>No CBOM posture available yet. Ingest a CycloneDX CBOM to populate cryptographic assets.</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 16, padding: '0 16px 16px' }}>
              <div className="summary-grid">
                {cbomPosture.map(summary => (
                  <button
                    key={summary.assetId}
                    type="button"
                    className={`summary-card${activeCbomAssetId === summary.assetId ? ' selected' : ''}`}
                    onClick={() => setSelectedCbomAssetId(summary.assetId)}
                    style={{ textAlign: 'left' }}
                  >
                    <span className="summary-label">{summary.assetName}</span>
                    <span className="summary-value">{formatScore(summary.postureScore)}</span>
                    <span className="summary-caption">
                      {summary.totalComponents} assets · {summary.criticalFindings} critical · {summary.highFindings} high
                    </span>
                  </button>
                ))}
              </div>

              {activeCbomAssetId && (
                <>
                  <div className="summary-grid">
                    {(() => {
                      const active = cbomPosture.find(p => p.assetId === activeCbomAssetId);
                      return [
                        ['Posture score', formatScore(active?.postureScore)],
                        ['Critical findings', active?.criticalFindings ?? 0],
                        ['Quantum-vulnerable', active?.quantumVulnerable ?? 0],
                        ['Certs expiring', active?.expiringCerts ?? 0],
                      ].map(([label, value]) => (
                        <div className="summary-card" key={label}>
                          <span className="summary-label">{label}</span>
                          <span className="summary-value">{value}</span>
                        </div>
                      ));
                    })()}
                  </div>

                  <div className="panel-subsection">
                    <div className="panel-header" style={{ padding: 0, marginBottom: 8 }}>
                      <h4>CBOM Components</h4>
                      <span className="panel-caption">Algorithms, certificates, protocols, and related cryptographic material.</span>
                    </div>
                    <table className="data-table" style={{ width: '100%' }}>
                      <thead>
                        <tr>
                          <th>Component</th>
                          <th>Asset Type</th>
                          <th>Primitive / Protocol</th>
                          <th>Key Size</th>
                          <th>State</th>
                          <th>Storage</th>
                          <th>Risk</th>
                          <th>Findings</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(cbomComponentsQuery.data ?? []).map((component: CbomComponent) => (
                          <tr key={component.id}>
                            <td>{component.name}</td>
                            <td>{component.assetType}</td>
                            <td>{displayValue(component.primitive ?? component.protocolVersion)}</td>
                            <td>{displayValue(component.keySize)}</td>
                            <td>{displayValue(component.state)}</td>
                            <td>{displayValue(component.storageLocation)}</td>
                            <td>{formatScore(component.riskScore)}</td>
                            <td>
                              <FindingSeverityChips
                                critical={component.criticalFindingCount}
                                high={component.highFindingCount}
                                other={Math.max(0, component.openFindingCount - component.criticalFindingCount - component.highFindingCount)}
                              />
                            </td>
                          </tr>
                        ))}
                        {(cbomComponentsQuery.data ?? []).length === 0 && (
                          <tr><td colSpan={8}>No CBOM components found for this asset.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  <div className="panel-subsection">
                    <div className="panel-header" style={{ padding: 0, marginBottom: 8 }}>
                      <h4>Open Findings</h4>
                      <select className="form-select" style={{ width: 180 }} value={cbomSeverityFilter} onChange={e => setCbomSeverityFilter(e.target.value)}>
                        <option value="">All severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                      </select>
                    </div>
                    <div style={{ display: 'grid', gap: 8 }}>
                      {(cbomFindingsQuery.data ?? []).map((finding: CbomRiskFinding) => (
                        <div key={finding.id} className="finding-card">
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                            <div>
                              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                                <strong>{finding.componentName}</strong>
                                <span className={`status-badge ${severityClass(finding.severity)}`}>{finding.severity}</span>
                                <span className="status-badge">{finding.riskClass}</span>
                              </div>
                              <p style={{ margin: '6px 0 0' }}>{finding.title}</p>
                              {finding.recommendation && <p className="panel-caption" style={{ marginTop: 4 }}>{finding.recommendation}</p>}
                            </div>
                            <button type="button" className="btn btn-secondary btn-inline" onClick={() => void acceptCbomFinding(finding)}>
                              Accept
                            </button>
                          </div>
                        </div>
                      ))}
                      {(cbomFindingsQuery.data ?? []).length === 0 && (
                        <div className="empty-state"><p>No open findings match the current filter.</p></div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </section>
      )}

      {/* ── GitHub Auto-Pipeline ── */}
      {includeGithubSources && (
        <section className="panel">
          <div className="panel-header">
            <h3>GitHub Auto-Pipeline</h3>
            <span className="panel-caption">Configure automated {BOM_META[bomType].short} ingestion from GitHub repositories or GHCR.</span>
          </div>

          {bomType === 'VENDOR' ? (
            <div className="ingestion-form">
              <div className="form-section">
                <div className="inline-note">GitHub auto-pipeline is not available for Vendor BOM — vendor-supplied files must be ingested via File Upload or URL Fetch above.</div>
              </div>
            </div>
          ) : (
            <div className="ingestion-form">
              {/* Source type + owner/repo/token */}
              <div className="form-section">
                <p className="form-section-title">Source</p>
                <div className="form-grid ingestion-grid">
                  <label>Source Type
                    <select value={ghSourcePath} onChange={e => setGhSourcePath(e.target.value)}>
                      {currentSourceOpts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </label>
                  <label>GitHub Owner
                    <input value={ghOwner} onChange={e => setGhOwner(e.target.value)} placeholder="org-name" />
                  </label>
                  {ghSourcePath === 'ghcr/attestations' ? (
                    <div className="inline-note">GHCR mode discovers all container packages under <code>ghcr.io/{ghOwner.trim() || 'owner'}</code>. Requires a token with <code>read:packages</code> scope.</div>
                  ) : (
                    <label>GitHub Repo{needsRepo ? '' : ' (optional — leave blank for all repos)'}
                      <input value={ghRepo} onChange={e => setGhRepo(e.target.value)} placeholder="service-repo" />
                      {currentSourceOpt?.hint && <span className="field-hint">{currentSourceOpt.hint}</span>}
                    </label>
                  )}
                  <label>GitHub Token <span style={{ fontWeight: 400, color: 'var(--muted)' }}>(optional)</span>
                    <input type="password" value={ghToken} onChange={e => setGhToken(e.target.value)}
                      placeholder="ghp_… leave blank to use the global backend token" autoComplete="new-password" />
                  </label>
                </div>
              </div>

              {/* Schedule (for saved pipelines) */}
              <div className="form-section">
                <p className="form-section-title">Schedule (saved pipelines only)</p>
                <div className="form-grid ingestion-grid">
                  <label>Pipeline Name
                    <input value={ghPipelineName} onChange={e => setGhPipelineName(e.target.value)} placeholder="payments-sbom-daily" />
                  </label>
                  <label>Frequency
                    <select value={ghFrequency} onChange={e => setGhFrequency(e.target.value as 'ONCE' | 'INTERVAL')}>
                      <option value="ONCE">Once</option>
                      <option value="INTERVAL">Every N hours</option>
                    </select>
                  </label>
                  {ghFrequency === 'INTERVAL' && (
                    <label>Interval (hours)
                      <input type="number" min={1} max={168} value={ghIntervalHours} onChange={e => setGhIntervalHours(e.target.value)} />
                    </label>
                  )}
                  <label>Enabled
                    <select value={ghEnabled ? 'true' : 'false'} onChange={e => setGhEnabled(e.target.value === 'true')}>
                      <option value="true">Enabled</option>
                      <option value="false">Disabled</option>
                    </select>
                  </label>
                </div>
              </div>

              <div className="button-row form-submit-row">
                <button type="button" className="btn btn-primary" disabled={pipelineBusy != null} onClick={() => void runPipelineOnce()}>
                  {pipelineBusy === 'run' ? 'Running…' : 'Run Once'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={pipelineBusy != null} onClick={() => void savePipeline()}>
                  {pipelineBusy === 'save' ? 'Saving…' : 'Save Pipeline'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={pipelineBusy != null}
                  onClick={() => void githubSourcesQuery.refetch()}>
                  Refresh
                </button>
              </div>

              {pipelineMsg && <div className="notice">{pipelineMsg}</div>}
            </div>
          )}

          {/* Saved pipelines table */}
          {githubSources.length > 0 && (
            <div style={{ padding: '0 16px 16px' }}>
              <p className="form-section-title" style={{ marginBottom: 8 }}>Saved Pipelines</p>
              <table className="data-table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th style={{ width: 32 }} />
                    <th>Name</th>
                    <th>Source</th>
                    <th>Asset</th>
                    <th>Schedule</th>
                    <th>Last Run</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {githubSources.map((src: GithubSbomSource) => {
                    const dot = pipelineStatusMeta(src.lastRunStatus);
                    return (
                      <tr key={src.id}>
                        <td><span className={`pipeline-dot ${dot.cls}`} title={src.lastError ? `${dot.label}: ${src.lastError}` : dot.label} /></td>
                        <td>{src.name}</td>
                        <td>{sourceTypeLabel(src.path)}: {src.path === 'ghcr/attestations' ? `ghcr.io/${src.owner}` : `${src.owner}/${src.repo}`}</td>
                        <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{src.assetName}</td>
                        <td>{src.frequency === 'ONCE' ? 'Once' : `Every ${Math.round(src.intervalMinutes / 60)}h`}</td>
                        <td>{src.lastRunAt ? new Date(src.lastRunAt).toLocaleString() : 'Never'}</td>
                        <td>
                          <button type="button" className="btn btn-secondary btn-inline"
                            disabled={pipelineBusy != null}
                            onClick={() => void runSavedPipeline(src.id)}>
                            {pipelineBusy === src.id ? 'Running…' : 'Run Now'}
                          </button>
                          <button type="button" className="btn btn-secondary btn-inline"
                            disabled={pipelineBusy != null}
                            onClick={() => void deleteSavedPipeline(src.id, src.name)}>
                            {pipelineBusy === `del:${src.id}` ? 'Deleting…' : 'Delete'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {githubSources.length === 0 && bomType !== 'VENDOR' && (
            <div className="empty-state" style={{ padding: '16px 16px 24px' }}>
              <p>No saved pipelines yet. Configure a source above and click <strong>Save Pipeline</strong> to schedule recurring ingestion.</p>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
