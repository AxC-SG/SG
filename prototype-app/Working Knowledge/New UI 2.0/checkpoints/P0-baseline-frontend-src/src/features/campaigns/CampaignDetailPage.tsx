import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { pathForFindingDetail, pathForInventoryHostAsset, pathForInventoryViewWithSearch, pathForSoftwareIdentityDetail, pathForVulnRepoView } from '../../app/routes';
import type { Finding } from '../findings/types';
import { api } from '../../api/client';
import { cveWorkbenchApi } from '../cve-workbench/api';
import type { OrgSpecificCveExposureRecord } from '../cve-workbench/types';
import type { Asset } from '../inventory/api-types';
import type { SoftwareIdentitySummary } from '../software-identities/types';
import type {
  CampaignAssetRow,
  CampaignDetail,
  CampaignExceptionStatus,
  CampaignSoftwareItem,
  CampaignStatus,
} from './types';

type DetailTab = 'overview' | 'products' | 'assets' | 'findings' | 'exceptions' | 'evidence' | 'activity';
type AssetAddTab = 'search' | 'tag' | 'class';

const ADD_ASSETS_PAGE_SIZE = 10;

function sevPill(severity?: string | null): string {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical') return 'severity-pill severity-critical';
  if (s === 'high') return 'severity-pill severity-high';
  if (s === 'medium') return 'severity-pill severity-medium';
  return 'severity-pill severity-low';
}

function statusPill(status?: string | null): string {
  const s = (status ?? '').toUpperCase();
  if (s === 'OPEN') return 'status-pill status-open';
  if (s === 'RESOLVED' || s === 'CLOSED') return 'status-pill status-resolved';
  if (s === 'SUPPRESSED') return 'status-pill status-suppressed';
  return 'status-pill';
}

function statusBadgeClass(status: CampaignStatus): string {
  if (status === 'ACTIVE') return 'campaign-status-badge active';
  if (status === 'PAUSED') return 'campaign-status-badge paused';
  if (status === 'BLOCKED') return 'campaign-status-badge blocked';
  if (status === 'CLOSED' || status === 'CANCELLED') return 'campaign-status-badge closed';
  if (status === 'IN_REVIEW') return 'campaign-status-badge review';
  return 'campaign-status-badge draft';
}

function formatStatus(status: CampaignStatus): string {
  return status.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatDate(value?: string | null): string {
  if (!value) return 'TBD';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function daysLeft(dueAt?: string | null): number | null {
  if (!dueAt) return null;
  const d = new Date(dueAt);
  if (Number.isNaN(d.getTime())) return null;
  return Math.ceil((d.getTime() - Date.now()) / 86_400_000);
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .join('');
}

type NotifyTemplate = 'exception_followup' | 'escalation' | 'nearing_due_date';

const NOTIFY_TEMPLATES: Record<NotifyTemplate, { label: string; subject: string; body: string }> = {
  exception_followup: {
    label: 'Exception Follow-up',
    subject: 'Exception Request Update — {{cve_id}} Remediation Campaign',
    body: 'Hi {{owner_name}},\n\nThis is a follow-up regarding an open exception request for the {{cve_id}} remediation campaign.\n\n• Affected assets: {{asset_count}}\n• Systems: {{asset_list}}\n• Exception due date: {{due_date}}\n• Severity: {{severity}}\n\nThe exception is currently pending review. Please ensure it is approved or rejected promptly to avoid delays in the remediation timeline.\n\nIf you have questions, please reach out to the security team.\n\nThank you,\nSecurity Operations',
  },
  escalation: {
    label: 'Escalation',
    subject: 'ESCALATION: Remediation Overdue — {{cve_id}} Requires Immediate Attention',
    body: 'Hi {{owner_name}},\n\nThis is an escalation notice for the {{cve_id}} remediation campaign. Immediate attention is required.\n\n• Affected assets: {{asset_count}}\n• Systems at risk: {{asset_list}}\n• Overdue since: {{due_date}}\n• Severity: {{severity}}\n\nThe remediation deadline has passed and affected systems remain unpatched. Leadership has been notified.\n\nPlease provide an updated remediation plan or submit an exception request within 24 hours.\n\nThank you,\nSecurity Operations',
  },
  nearing_due_date: {
    label: 'Nearing Due Date',
    subject: 'Action Required: {{cve_id}} Remediation Due {{due_date}}',
    body: 'Hi {{owner_name}},\n\nThis is a reminder that the remediation deadline for {{cve_id}} is approaching.\n\n• Affected assets: {{asset_count}}\n• Systems: {{asset_list}}\n• Severity: {{severity}}\n• Due date: {{due_date}}\n\nPlease ensure all affected systems are remediated before the due date to avoid an SLA breach.\n\nIf you require additional time, please submit an exception request as soon as possible.\n\nThank you,\nSecurity Operations',
  },
};

const NOTIFY_VARIABLES = ['{{owner_name}}', '{{asset_count}}', '{{asset_list}}', '{{cve_id}}', '{{due_date}}', '{{severity}}'] as const;

export function CampaignDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [detail, setDetail] = React.useState<CampaignDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<DetailTab>('overview');
  const [statusBusy, setStatusBusy] = React.useState<CampaignStatus | null>(null);
  const [noteDraft, setNoteDraft] = React.useState('');
  const [savingNote, setSavingNote] = React.useState(false);
  const [exceptionStatusBusy, setExceptionStatusBusy] = React.useState<string | null>(null);

  // ── Sidebar collapse state ────────────────────────────────────────────────
  const [advisoriesCollapsed, setAdvisoriesCollapsed] = React.useState(false);
  const [notifyCollapsed, setNotifyCollapsed] = React.useState(false);

  // ── Notify modal ──────────────────────────────────────────────────────────
  const [showNotify, setShowNotify] = React.useState(false);
  const [notifyRecipients, setNotifyRecipients] = React.useState<Set<string>>(new Set());
  const [notifyTemplate, setNotifyTemplate] = React.useState<NotifyTemplate>('nearing_due_date');
  const [notifySubject, setNotifySubject] = React.useState('');
  const [notifyBody, setNotifyBody] = React.useState('');
  const [notifySent, setNotifySent] = React.useState(false);
  const notifyBodyRef = React.useRef<HTMLTextAreaElement>(null);

  // ── AI Campaign Insights ──────────────────────────────────────────────────
  const [aiInsights, setAiInsights] = React.useState<string | null>(null);
  const [aiInsightsLoading, setAiInsightsLoading] = React.useState(false);
  const [aiInsightsError, setAiInsightsError] = React.useState<string | null>(null);
  const [aiInsightsGeneratedAt, setAiInsightsGeneratedAt] = React.useState<string | null>(null);

  // Load persisted insights from localStorage
  React.useEffect(() => {
    if (!id) return;
    try {
      const saved = localStorage.getItem(`campaign-insights-${id}`);
      if (saved) {
        const parsed = JSON.parse(saved) as { text: string; generatedAt: string };
        setAiInsights(parsed.text);
        setAiInsightsGeneratedAt(parsed.generatedAt);
      }
    } catch { /* ignore parse errors */ }
  }, [id]);

  // ── Advisories ────────────────────────────────────────────────────────────
  type Advisory = { title: string; cveId: string; severity: string; type: string; summary: string; publishedDate?: string };
  const [advisories, setAdvisories] = React.useState<Advisory[] | null>(null);
  const [advisoriesLoading, setAdvisoriesLoading] = React.useState(false);
  const [advisoriesError, setAdvisoriesError] = React.useState<string | null>(null);
  const [advisoriesFetchedAt, setAdvisoriesFetchedAt] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!id) return;
    try {
      const saved = localStorage.getItem(`campaign-advisories-${id}`);
      if (saved) {
        const parsed = JSON.parse(saved) as { items: Advisory[]; fetchedAt: string };
        setAdvisories(parsed.items);
        setAdvisoriesFetchedAt(parsed.fetchedAt);
      }
    } catch { /* ignore */ }
  }, [id]);

  // ── Add Assets modal ─────────────────────────────────────────────────────
  const [showAddAssets, setShowAddAssets] = React.useState(false);
  const [addAssetsTab, setAddAssetsTab] = React.useState<AssetAddTab>('search');
  const [availableAssets, setAvailableAssets] = React.useState<Asset[]>([]);
  const [assetsLoading, setAssetsLoading] = React.useState(false);
  // search tab
  const [assetSearch, setAssetSearch] = React.useState('');
  const [selectedAssetIds, setSelectedAssetIds] = React.useState<Set<string>>(new Set());
  const [assetPage, setAssetPage] = React.useState(0);
  // tag tab
  const [assetTagInput, setAssetTagInput] = React.useState('');
  // class tab
  const [assetClassSel, setAssetClassSel] = React.useState<Set<string>>(new Set());
  // shared
  const [addAssetsError, setAddAssetsError] = React.useState('');

  React.useEffect(() => {
    if (!showAddAssets) return;
    setAssetsLoading(true);
    setAvailableAssets([]);
    api.listAssets()
      .then((assets) => setAvailableAssets(assets))
      .catch((err) => setAddAssetsError(err instanceof Error ? err.message : String(err)))
      .finally(() => setAssetsLoading(false));
  }, [showAddAssets]);

  function closeAddAssets() {
    setShowAddAssets(false);
    setAddAssetsTab('search');
    setAssetSearch('');
    setSelectedAssetIds(new Set());
    setAssetPage(0);
    setAssetTagInput('');
    setAssetClassSel(new Set());
    setAddAssetsError('');
  }
  function toggleAssetId(assetId: string) {
    setSelectedAssetIds((prev) => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId); else next.add(assetId);
      return next;
    });
  }
  function toggleAssetClass(cls: string) {
    setAssetClassSel((prev) => {
      const next = new Set(prev);
      if (next.has(cls)) next.delete(cls); else next.add(cls);
      return next;
    });
  }

  function resolveAssetsToAdd(): Asset[] {
    const existingIds = new Set(detail?.assets.map((a) => a.assetIdentifier).filter(Boolean));
    if (addAssetsTab === 'search') {
      return availableAssets.filter((a) => selectedAssetIds.has(a.id) && !existingIds.has(a.identifier));
    }
    if (addAssetsTab === 'tag') {
      const tags = assetTagInput.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
      if (tags.length === 0) return [];
      return availableAssets.filter((a) => {
        const haystack = [a.name, a.identifier, a.environment ?? '', a.ownerTeam ?? '', a.type, a.businessCriticality].join(' ').toLowerCase();
        return tags.some((tag) => haystack.includes(tag)) && !existingIds.has(a.identifier);
      });
    }
    // class tab
    return availableAssets.filter((a) => assetClassSel.has(a.type) && !existingIds.has(a.identifier));
  }

  function submitAddAssets() {
    const assetsToAdd = resolveAssetsToAdd();
    if (assetsToAdd.length === 0) {
      setAddAssetsError('No new assets matched — they may already be in this campaign.');
      return;
    }
    const newRows: CampaignAssetRow[] = assetsToAdd.map((a) => ({
      assetId: a.id,
      assetName: a.name,
      assetIdentifier: a.identifier,
      environment: a.environment ?? null,
      supportGroup: a.ownerTeam ?? null,
      openFindings: 0,
      resolvedFindings: 0,
    }));
    setDetail((prev) =>
      prev
        ? {
            ...prev,
            assets: [...prev.assets, ...newRows],
            summary: { ...prev.summary, assetCount: prev.summary.assetCount + newRows.length },
          }
        : prev,
    );
    closeAddAssets();
  }

  // ── Add CVE modal ────────────────────────────────────────────────────────
  const [showAddCve, setShowAddCve] = React.useState(false);
  const [availableCves, setAvailableCves] = React.useState<OrgSpecificCveExposureRecord[]>([]);
  const [cvesLoading, setCvesLoading] = React.useState(false);
  const [cveSearchInput, setCveSearchInput] = React.useState('');
  const [cveSearchQuery, setCveSearchQuery] = React.useState('');
  const [cvePage, setCvePage] = React.useState(0);
  const [cveTotalPages, setCveTotalPages] = React.useState(1);
  const [cveTotalItems, setCveTotalItems] = React.useState(0);
  // Map<externalId, record> so we remember selections across page turns
  const [selectedCveMap, setSelectedCveMap] = React.useState<Map<string, OrgSpecificCveExposureRecord>>(new Map());
  const [addCveError, setAddCveError] = React.useState('');

  // Debounce search input → query
  React.useEffect(() => {
    const t = setTimeout(() => { setCveSearchQuery(cveSearchInput); setCvePage(0); }, 300);
    return () => clearTimeout(t);
  }, [cveSearchInput]);

  // Load CVEs when modal opens or page/query changes
  React.useEffect(() => {
    if (!showAddCve) return;
    setCvesLoading(true);
    cveWorkbenchApi.listOrgSpecificCves({ page: cvePage, size: 10, query: cveSearchQuery || undefined })
      .then((result: import('../cve-workbench/types').OrgSpecificCveExposurePage) => {
        setAvailableCves(result.items);
        setCveTotalPages(Math.max(1, result.totalPages));
        setCveTotalItems(result.totalItems);
      })
      .catch((err: unknown) => setAddCveError(err instanceof Error ? err.message : String(err)))
      .finally(() => setCvesLoading(false));
  }, [showAddCve, cvePage, cveSearchQuery]);

  function closeAddCve() {
    setShowAddCve(false);
    setCveSearchInput('');
    setCveSearchQuery('');
    setCvePage(0);
    setCveTotalPages(1);
    setCveTotalItems(0);
    setAvailableCves([]);
    setSelectedCveMap(new Map());
    setAddCveError('');
  }
  function toggleCveSelection(rec: OrgSpecificCveExposureRecord) {
    setSelectedCveMap((prev) => {
      const next = new Map(prev);
      if (next.has(rec.externalId)) next.delete(rec.externalId); else next.set(rec.externalId, rec);
      return next;
    });
  }
  function submitAddCve() {
    const existing = new Set(detail?.summary.cveIds ?? []);
    const toAdd = Array.from(selectedCveMap.values()).filter((r) => !existing.has(r.externalId));
    if (toAdd.length === 0) {
      setAddCveError('All selected CVEs are already tracked in this campaign.');
      return;
    }
    setDetail((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        summary: { ...prev.summary, cveIds: [...prev.summary.cveIds, ...toAdd.map((r) => r.externalId)] },
        vulnerabilities: [
          ...prev.vulnerabilities,
          ...toAdd.map((r) => ({ externalId: r.externalId, title: r.title, severity: r.severity })),
        ],
      };
    });
    closeAddCve();
  }

  // ── Add Software modal ────────────────────────────────────────────────────
  const [showAddSoftware, setShowAddSoftware] = React.useState(false);
  const [availableSoftware, setAvailableSoftware] = React.useState<SoftwareIdentitySummary[]>([]);
  const [softwareLoading, setSoftwareLoading] = React.useState(false);
  const [softwareSearchInput, setSoftwareSearchInput] = React.useState('');
  const [softwareSearchQuery, setSoftwareSearchQuery] = React.useState('');
  const [softwarePage, setSoftwarePage] = React.useState(0);
  const [softwareTotalPages, setSoftwareTotalPages] = React.useState(1);
  const [softwareTotalItems, setSoftwareTotalItems] = React.useState(0);
  const [selectedSoftwareMap, setSelectedSoftwareMap] = React.useState<Map<string, SoftwareIdentitySummary>>(new Map());
  const [addSoftwareError, setAddSoftwareError] = React.useState('');

  React.useEffect(() => {
    const t = setTimeout(() => { setSoftwareSearchQuery(softwareSearchInput); setSoftwarePage(0); }, 300);
    return () => clearTimeout(t);
  }, [softwareSearchInput]);

  React.useEffect(() => {
    if (!showAddSoftware) return;
    setSoftwareLoading(true);
    api.listSoftwareIdentities({ page: softwarePage, size: 10, query: softwareSearchQuery || undefined })
      .then((result) => {
        setAvailableSoftware(result.content);
        setSoftwareTotalPages(Math.max(1, result.totalPages));
        setSoftwareTotalItems(result.totalElements);
      })
      .catch((err: unknown) => setAddSoftwareError(err instanceof Error ? err.message : String(err)))
      .finally(() => setSoftwareLoading(false));
  }, [showAddSoftware, softwarePage, softwareSearchQuery]);

  // Initialize notify modal when opened
  React.useEffect(() => {
    if (!showNotify) return;
    setNotifyRecipients(new Set((detail?.notifyGroups ?? []).map((g) => g.id)));
    setNotifyTemplate('nearing_due_date');
    setNotifySent(false);
    setNotifySubject(NOTIFY_TEMPLATES.nearing_due_date.subject);
    setNotifyBody(NOTIFY_TEMPLATES.nearing_due_date.body);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showNotify]);

  // Update subject/body when template changes
  React.useEffect(() => {
    if (!showNotify) return;
    setNotifySubject(NOTIFY_TEMPLATES[notifyTemplate].subject);
    setNotifyBody(NOTIFY_TEMPLATES[notifyTemplate].body);
  }, [notifyTemplate, showNotify]);

  function closeNotify() {
    setShowNotify(false);
    setNotifySent(false);
  }

  function insertVariable(v: string) {
    const el = notifyBodyRef.current;
    if (!el) { setNotifyBody((prev) => `${prev} ${v}`); return; }
    const start = el.selectionStart ?? notifyBody.length;
    const end = el.selectionEnd ?? notifyBody.length;
    setNotifyBody(notifyBody.slice(0, start) + v + notifyBody.slice(end));
    setTimeout(() => {
      el.focus();
      el.setSelectionRange(start + v.length, start + v.length);
    }, 0);
  }

  function closeAddSoftware() {
    setShowAddSoftware(false);
    setSoftwareSearchInput('');
    setSoftwareSearchQuery('');
    setSoftwarePage(0);
    setSoftwareTotalPages(1);
    setSoftwareTotalItems(0);
    setAvailableSoftware([]);
    setSelectedSoftwareMap(new Map());
    setAddSoftwareError('');
  }
  function toggleSoftwareSelection(sw: SoftwareIdentitySummary) {
    setSelectedSoftwareMap((prev) => {
      const next = new Map(prev);
      if (next.has(sw.id)) next.delete(sw.id); else next.set(sw.id, sw);
      return next;
    });
  }
  function submitAddSoftware() {
    const existing = new Set((detail?.softwareItems ?? []).map((s) => s.id));
    const toAdd = Array.from(selectedSoftwareMap.values()).filter((sw) => !existing.has(sw.id));
    if (toAdd.length === 0) {
      setAddSoftwareError('All selected software is already tracked in this campaign.');
      return;
    }
    const newItems: CampaignSoftwareItem[] = toAdd.map((sw) => ({
      id: sw.id,
      displayName: sw.displayName,
      vendor: sw.vendor ?? null,
      assetCount: sw.assetCount,
      openFindingCount: sw.openFindingCount,
    }));
    setDetail((prev) => prev ? { ...prev, softwareItems: [...(prev.softwareItems ?? []), ...newItems] } : prev);
    closeAddSoftware();
  }

  // ── Delete helpers ────────────────────────────────────────────────────────
  function deleteAsset(identifier: string | null, name: string | null) {
    setDetail((prev) => {
      if (!prev) return prev;
      const assets = prev.assets.filter(
        (a) => !(a.assetIdentifier === identifier && a.assetName === name),
      );
      return { ...prev, assets, summary: { ...prev.summary, assetCount: assets.length } };
    });
  }
  function deleteCve(cveId: string) {
    setDetail((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        summary: { ...prev.summary, cveIds: prev.summary.cveIds.filter((id) => id !== cveId) },
        vulnerabilities: prev.vulnerabilities.filter((v) => v.externalId !== cveId),
      };
    });
  }
  function deleteSoftwareItem(itemId: string) {
    setDetail((prev) => prev ? { ...prev, softwareItems: (prev.softwareItems ?? []).filter((s) => s.id !== itemId) } : prev);
  }

  const reload = React.useCallback(async () => {
    if (!id) return;
    try {
      const result = await api.getCampaign(id);
      setDetail(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [id]);

  React.useEffect(() => {
    if (!id) return;
    setLoading(true);
    api.getCampaign(id)
      .then((d) => setDetail(d))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, [id]);

  async function transition(status: CampaignStatus): Promise<void> {
    if (!id) return;
    setStatusBusy(status);
    try {
      const updated = await api.updateCampaignStatus(id, status);
      setDetail(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStatusBusy(null);
    }
  }

  async function submitNote(): Promise<void> {
    if (!id || !noteDraft.trim()) return;
    setSavingNote(true);
    try {
      await api.addCampaignNote(id, noteDraft.trim());
      setNoteDraft('');
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingNote(false);
    }
  }

  async function updateExceptionStatus(exceptionId: string, status: CampaignExceptionStatus): Promise<void> {
    if (!id) return;
    setExceptionStatusBusy(exceptionId + status);
    try {
      const updated = await api.updateCampaignExceptionStatus(id, exceptionId, status);
      setDetail(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExceptionStatusBusy(null);
    }
  }

  if (loading) {
    return <div className="cd-loading">Loading campaign…</div>;
  }

  if (error || !detail) {
    return (
      <div className="cd-loading">
        <p>{error ?? 'Campaign not found.'}</p>
        <button type="button" className="btn btn-secondary" onClick={() => navigate('/vuln-repo/campaigns')}>
          Back to Campaigns
        </button>
      </div>
    );
  }

  const s = detail.summary;
  const left = daysLeft(s.dueAt);
  const pct = s.completionPercent;
  const notifyOwner = detail.notifyGroups[0];
  const notifyResolver = detail.notifyGroups[1] ?? detail.notifyGroups[0];
  const cveLabel = s.cveIds.join(', ');

  // ── Overview computed values ─────────────────────────────────────────────
  const nowMs = Date.now();
  const overdueCount = detail.findings.filter(
    (f) => f.status !== 'RESOLVED' && f.dueAt != null && new Date(f.dueAt).getTime() < nowMs,
  ).length;
  const criticalExposed = detail.findings.filter(
    (f) => (f.severity ?? '').toUpperCase() === 'CRITICAL' && f.status !== 'RESOLVED',
  ).length;

  type SevStats = { total: number; resolved: number; overdue: number };
  const sevStatMap = new Map<string, SevStats>();
  for (const f of detail.findings) {
    const sev = (f.severity ?? 'UNKNOWN').toUpperCase();
    const eg = sevStatMap.get(sev) ?? { total: 0, resolved: 0, overdue: 0 };
    const isOverdue = f.status !== 'RESOLVED' && f.dueAt != null && new Date(f.dueAt).getTime() < nowMs;
    sevStatMap.set(sev, {
      total: eg.total + 1,
      resolved: eg.resolved + (f.status === 'RESOLVED' ? 1 : 0),
      overdue: eg.overdue + (isOverdue ? 1 : 0),
    });
  }
  const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const sevRows = SEV_ORDER.map((sev) => ({ sev, ...(sevStatMap.get(sev) ?? { total: 0, resolved: 0, overdue: 0 }) })).filter((r) => r.total > 0);

  type TeamStats = { group: string; total: number; resolved: number; overdue: number };
  const teamStatMap = new Map<string, TeamStats>();
  for (const f of detail.findings) {
    const grp = f.ownerGroup ?? 'Unassigned';
    const eg = teamStatMap.get(grp) ?? { group: grp, total: 0, resolved: 0, overdue: 0 };
    const isOverdue = f.status !== 'RESOLVED' && f.dueAt != null && new Date(f.dueAt).getTime() < nowMs;
    teamStatMap.set(grp, {
      group: grp,
      total: eg.total + 1,
      resolved: eg.resolved + (f.status === 'RESOLVED' ? 1 : 0),
      overdue: eg.overdue + (isOverdue ? 1 : 0),
    });
  }
  const teamRows = Array.from(teamStatMap.values()).sort((a, b) => b.total - a.total);

  // Lifecycle stage index: 0=Discovery 1=Assessment 2=Remediation 3=Verification 4=Closure
  let stageIdx = 2;
  if (s.status === 'DRAFT') stageIdx = 0;
  else if (s.status === 'CLOSED' || s.status === 'CANCELLED') stageIdx = 4;
  else if (s.status === 'IN_REVIEW') stageIdx = 3;
  else if (pct < 10) stageIdx = 1;

  const LIFECYCLE_STAGES = [
    { label: 'Discovery', sub: 'Scope & identify affected systems' },
    { label: 'Assessment', sub: 'Confirm applicability & risk scoring' },
    { label: 'Remediation', sub: 'Patch, mitigate, or defer findings' },
    { label: 'Verification', sub: 'Validate fixes & rescan assets' },
    { label: 'Closure', sub: 'Sign-off, exceptions, lessons learned' },
  ];

  // ── Impacted products — unique packages from findings ───────────────────
  type ProductRow = { name: string; assets: Set<string>; total: number; resolved: number; maxSev: string | null };
  const productMap = new Map<string, ProductRow>();
  for (const f of detail.findings) {
    const pkg = f.packageName || '(unknown package)';
    const pr = productMap.get(pkg) ?? { name: pkg, assets: new Set<string>(), total: 0, resolved: 0, maxSev: null };
    if (f.assetName) pr.assets.add(f.assetName);
    pr.total++;
    if (f.status === 'RESOLVED') pr.resolved++;
    const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if (f.severity && (pr.maxSev == null || (SEV_RANK[f.severity.toUpperCase()] ?? 0) > (SEV_RANK[pr.maxSev.toUpperCase()] ?? 0))) {
      pr.maxSev = f.severity;
    }
    productMap.set(pkg, pr);
  }
  const productRows = Array.from(productMap.values()).sort((a, b) => {
    const RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (RANK[(b.maxSev ?? '').toUpperCase()] ?? 0) - (RANK[(a.maxSev ?? '').toUpperCase()] ?? 0);
  });

  // ── AI Insights generator (uses computed values from above) ──────────────
  async function generateAiInsights(): Promise<void> {
    if (!id) return;
    setAiInsightsLoading(true);
    setAiInsightsError(null);

    try {
      const response = await api.generateCampaignAiInsights(id);
      const text = response.text?.trim() ?? '';
      const generatedAt = response.generatedAt;
      setAiInsights(text);
      setAiInsightsGeneratedAt(generatedAt);
      localStorage.setItem(`campaign-insights-${id}`, JSON.stringify({ text, generatedAt }));
    } catch (err: unknown) {
      setAiInsightsError(err instanceof Error ? err.message : String(err));
    } finally {
      setAiInsightsLoading(false);
    }
  }

  async function fetchAdvisories(): Promise<void> {
    if (!id) return;
    setAdvisoriesLoading(true);
    setAdvisoriesError(null);

    try {
      const response = await api.generateCampaignAiAdvisories(id);
      const parsed = (response.advisories ?? []) as Advisory[];
      const fetchedAt = response.generatedAt;
      setAdvisories(parsed);
      setAdvisoriesFetchedAt(fetchedAt);
      localStorage.setItem(`campaign-advisories-${id}`, JSON.stringify({ items: parsed, fetchedAt }));
    } catch (err: unknown) {
      setAdvisoriesError(err instanceof Error ? err.message : String(err));
    } finally {
      setAdvisoriesLoading(false);
    }
  }

  // Split findings: suppressed/deferred go to Exceptions pill, active stay in Findings tab
  const suppressedFindings = detail.findings.filter(
    (f) => f.status.toUpperCase() === 'SUPPRESSED' || f.status.toUpperCase() === 'DEFERRED',
  );
  const activeFindings = detail.findings.filter(
    (f) => f.status.toUpperCase() !== 'SUPPRESSED' && f.status.toUpperCase() !== 'DEFERRED',
  );

  const TABS: { key: DetailTab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'products', label: 'Impacted Products', count: productRows.length },
    { key: 'assets', label: 'Assets', count: s.assetCount },
    { key: 'findings', label: 'Findings', count: activeFindings.length },
    { key: 'exceptions', label: 'Exceptions', count: s.exceptionCount + suppressedFindings.length },
    { key: 'evidence', label: 'Vulnerabilities', count: s.cveIds.length },
    { key: 'activity', label: 'Activity' },
  ];

  return (
    <div className="cd-page">
      {/* ── Top bar ───────────────────────────────────────────────── */}
      <div className="cd-topbar">
        <div className="cd-breadcrumb">
          <button type="button" className="cd-breadcrumb-link" onClick={() => navigate('/vuln-repo/campaigns')}>
            Campaigns
          </button>
          <span className="cd-breadcrumb-sep">/</span>
          <span className="cd-breadcrumb-current">{s.name}</span>
        </div>
        <div className="cd-topbar-actions">
          <button type="button" className="btn btn-secondary" disabled={statusBusy !== null && statusBusy !== 'PAUSED'} onClick={() => void transition('PAUSED')}>
            {statusBusy === 'PAUSED' ? '…' : 'Pause'}
          </button>
          <button type="button" className="btn btn-secondary" disabled={statusBusy !== null && statusBusy !== 'ACTIVE'} onClick={() => void transition('ACTIVE')}>
            {statusBusy === 'ACTIVE' ? '…' : 'Resume'}
          </button>
          <button type="button" className="btn btn-secondary" disabled={statusBusy !== null && statusBusy !== 'IN_REVIEW'} onClick={() => void transition('IN_REVIEW')}>
            {statusBusy === 'IN_REVIEW' ? '…' : 'Move to Review'}
          </button>
          <button type="button" className="btn btn-secondary" disabled={statusBusy !== null && statusBusy !== 'BLOCKED'} onClick={() => void transition('BLOCKED')}>
            {statusBusy === 'BLOCKED' ? '…' : 'Mark Blocked'}
          </button>
          <button type="button" className="btn btn-primary" disabled={statusBusy !== null && statusBusy !== 'CLOSED'} onClick={() => void transition('CLOSED')}>
            {statusBusy === 'CLOSED' ? 'Closing…' : 'Close Campaign'}
          </button>
        </div>
      </div>

      {/* ── Sub-nav tabs ─────────────────────────────────────────── */}
      <div className="cd-tabnav">
        {TABS.map(({ key, label, count }) => (
          <button
            key={key}
            type="button"
            className={tab === key ? 'cd-tab active' : 'cd-tab'}
            onClick={() => setTab(key)}
          >
            {label}
            {count != null && (
              <span className={`cd-tab-count ${key === 'exceptions' && count > 0 ? 'warn' : ''}`}>
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {error && <div className="notice error" style={{ margin: '0 24px 12px' }}>{error}</div>}

      {/* ── Tab content ──────────────────────────────────────────── */}
      <div className="cd-body">
        {tab === 'overview' && (
          <div className="cd-overview-layout">
            {/* ── Main column ── */}
            <div className="cd-overview-main">

              {/* Hero card — campaign identity + threat context */}
              <div className="cd-hero-card">
                <div className="cd-status-meta">
                  <span className={statusBadgeClass(s.status)}>{formatStatus(s.status)}</span>
                  {s.startedAt && <span>· Created {formatDate(s.startedAt)}</span>}
                </div>
                <div className="cd-hero-title-row">
                  <h2 className="cd-hero-title">{s.name}</h2>
                  {(() => {
                    const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
                    const maxSev = detail.vulnerabilities.reduce<string | null>((best, v) => {
                      if (!v.severity) return best;
                      if (best === null || (SEV_RANK[v.severity.toUpperCase()] ?? 0) > (SEV_RANK[best.toUpperCase()] ?? 0)) return v.severity;
                      return best;
                    }, null);
                    return maxSev ? <span className={`cd-severity-badge cd-severity-badge--${maxSev.toLowerCase()}`}>{maxSev}</span> : null;
                  })()}
                </div>
                {s.summary && <div className="cd-hero-meta">{s.summary}</div>}

                {/* AI Campaign Insights */}
                <div className="cd-ai-insights">
                  <div className="cd-ai-insights-header">
                    <span className="cd-ai-insights-title">
                      <span className="cd-ai-icon">✦</span>
                      Campaign Insights
                    </span>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      {aiInsightsGeneratedAt && (
                        <span className="cd-ai-meta">
                          {new Date(aiInsightsGeneratedAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </span>
                      )}
                      <button
                        type="button"
                        className="cd-ai-btn"
                        disabled={aiInsightsLoading}
                        onClick={() => void generateAiInsights()}
                      >
                        {aiInsightsLoading ? (
                          <span className="cd-ai-spinner" />
                        ) : aiInsights ? (
                          '↻ Regenerate'
                        ) : (
                          '✦ Generate Insights'
                        )}
                      </button>
                    </div>
                  </div>

                  {aiInsightsError && (
                    <div className="cd-ai-error">{aiInsightsError}</div>
                  )}

                  {aiInsightsLoading && (
                    <div className="cd-ai-loading">
                      <span className="cd-ai-spinner" />
                      Analysing campaign data…
                    </div>
                  )}

                  {!aiInsightsLoading && !aiInsights && !aiInsightsError && (
                    <div className="cd-ai-empty">
                      Generate AI-powered insights covering remediation velocity, team accountability, CVE risk, and leadership priorities.
                    </div>
                  )}

                  {!aiInsightsLoading && aiInsights && (
                    <div className="cd-ai-content">
                      {aiInsights.split('\n').filter((line) => line.trim()).map((line, i) => {
                        const clean = line.replace(/^[\s\-*•\d.]+/, '').trim();
                        if (!clean) return null;
                        return (
                          <div key={i} className="cd-ai-point">
                            <span className="cd-ai-point-dot" />
                            <span>{clean}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* KPI tiles — exposure snapshot */}
              <div className="cd-kpi-grid">
                <div className="cd-kpi-tile">
                  <strong className="cd-kpi-value">{s.assetCount}</strong>
                  <span className="cd-kpi-label">Assets Affected</span>
                </div>
                <div className="cd-kpi-tile">
                  <strong className="cd-kpi-value">{s.openFindings}</strong>
                  <span className="cd-kpi-label">Open Findings</span>
                </div>
                <div className={`cd-kpi-tile${criticalExposed > 0 ? ' cd-kpi-tile--danger' : ''}`}>
                  <strong className="cd-kpi-value">{criticalExposed}</strong>
                  <span className="cd-kpi-label">Critical Exposed</span>
                </div>
                <div className={`cd-kpi-tile${overdueCount > 0 ? ' cd-kpi-tile--warn' : ''}`}>
                  <strong className="cd-kpi-value">{overdueCount}</strong>
                  <span className="cd-kpi-label">Overdue</span>
                </div>
                <div className={`cd-kpi-tile${s.exceptionCount > 0 ? ' cd-kpi-tile--warn' : ''}`}>
                  <strong className="cd-kpi-value">{s.exceptionCount}</strong>
                  <span className="cd-kpi-label">Exceptions</span>
                </div>
              </div>

              {/* Campaign lifecycle stage rail */}
              <div className="cd-stage-card">
                <div className="cd-group-section-label">CAMPAIGN STAGE</div>
                <div className="cd-stage-rail">
                  {LIFECYCLE_STAGES.map((stage, i) => {
                    const isDone = i < stageIdx;
                    const isActive = i === stageIdx;
                    const isBlocked = isActive && s.status === 'BLOCKED';
                    return (
                      <React.Fragment key={stage.label}>
                        {i > 0 && <div className={`cd-stage-connector${isDone ? ' done' : ''}`} />}
                        <div className={[
                          'cd-stage',
                          isActive ? 'cd-stage--active' : '',
                          isDone ? 'cd-stage--done' : '',
                          isBlocked ? 'cd-stage--blocked' : '',
                        ].filter(Boolean).join(' ')}>
                          <div className="cd-stage-dot">{isDone ? '✓' : isBlocked ? '!' : i + 1}</div>
                          <div className="cd-stage-label">{stage.label}</div>
                          {isActive && <div className="cd-stage-sub">{stage.sub}</div>}
                        </div>
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* Remediation progress — overall bar + per-severity breakdown */}
              <div className="cd-progress-card">
                <div className="cd-progress-header">
                  <span className="cd-progress-title">Remediation Progress</span>
                  <span className="cd-progress-summary">{pct}% · {s.resolvedFindings} of {s.totalFindings} findings resolved</span>
                </div>
                <div className="cd-progress-bar-wrap">
                  <div className="cd-progress-bar">
                    <div className="cd-progress-fill" style={{ width: `${pct}%` }} />
                  </div>
                </div>
                <div className="cd-progress-labels">
                  <span>0%</span>
                  <span className="cd-progress-resolved">{s.resolvedFindings} resolved</span>
                  <span>100%</span>
                </div>

                {/* By-severity breakdown */}
                {sevRows.length > 0 && (
                  <>
                    <div className="cd-group-section-label" style={{ marginTop: 18 }}>BY SEVERITY</div>
                    <div className="cd-sev-rows">
                      {sevRows.map((row) => {
                        const rowPct = row.total > 0 ? Math.round((row.resolved / row.total) * 100) : 0;
                        return (
                          <div key={row.sev} className="cd-sev-row">
                            <span className={`${sevPill(row.sev)} cd-sev-pill`}>{row.sev}</span>
                            <div className="cd-sev-bar-wrap">
                              <div className="cd-sev-bar">
                                <div className={`cd-sev-bar-fill cd-sev-bar-fill--${row.sev.toLowerCase()}`} style={{ width: `${rowPct}%` }} />
                              </div>
                            </div>
                            <span className="cd-sev-pct">{rowPct}%</span>
                            <span className="cd-sev-counts">{row.resolved}/{row.total}</span>
                            {row.overdue > 0 && <span className="cd-sev-overdue">{row.overdue} overdue</span>}
                          </div>
                        );
                      })}
                    </div>
                  </>
                )}

                {/* Team accountability */}
                {teamRows.length > 0 && (
                  <>
                    <div className="cd-group-section-label" style={{ marginTop: 20 }}>TEAM ACCOUNTABILITY</div>
                    <div className="cd-team-table">
                      <div className="cd-team-row cd-team-row--header">
                        <span>TEAM</span>
                        <span>ASSIGNED</span>
                        <span>RESOLVED</span>
                        <span>OVERDUE</span>
                        <span>STATUS</span>
                      </div>
                      {teamRows.map((row) => {
                        const rowPct = row.total > 0 ? Math.round((row.resolved / row.total) * 100) : 0;
                        const isBlocked = row.overdue > 0 && rowPct < 30;
                        const isAtRisk = row.overdue > 0;
                        const pillCls = isBlocked ? 'cd-team-pill--blocked' : isAtRisk ? 'cd-team-pill--atrisk' : 'cd-team-pill--ok';
                        const pillLabel = isBlocked ? 'At Risk' : isAtRisk ? 'Delayed' : 'On Track';
                        return (
                          <div key={row.group} className="cd-team-row">
                            <span className="cd-team-name">{row.group}</span>
                            <span className="cd-team-num">{row.total}</span>
                            <span className="cd-team-num cd-team-num--resolved">{row.resolved}</span>
                            <span className={`cd-team-num${row.overdue > 0 ? ' cd-team-num--overdue' : ''}`}>{row.overdue}</span>
                            <span className={`cd-team-pill ${pillCls}`}>{pillLabel}</span>
                          </div>
                        );
                      })}
                    </div>
                  </>
                )}
              </div>

            </div>

            {/* ── Right sidebar ── */}
            <div className="cd-overview-sidebar">

              {/* SLA Countdown */}
              <div className="cd-sidebar-card">
                <div className="cd-sidebar-card-title">SLA COUNTDOWN</div>
                {left != null ? (
                  <div className={`cd-sla-countdown${left <= 0 ? ' cd-sla-countdown--overdue' : left <= 7 ? ' cd-sla-countdown--critical' : left <= 14 ? ' cd-sla-countdown--warn' : ''}`}>
                    <strong className="cd-sla-days">{Math.abs(left)}</strong>
                    <span className="cd-sla-days-label">{left <= 0 ? 'days overdue' : 'days remaining'}</span>
                    <div className="cd-sla-bar-wrap">
                      <div className="cd-sla-bar">
                        <div className="cd-sla-bar-fill" style={{
                          width: `${Math.min(100, Math.max(0, pct))}%`,
                          background: left <= 0 ? '#ef4444' : left <= 7 ? '#f59e0b' : '#21d07a',
                        }} />
                      </div>
                    </div>
                    <span className="cd-sla-due-label">Target: {formatDate(s.dueAt)}</span>
                  </div>
                ) : (
                  <span className="cd-detail-label">No due date set</span>
                )}
              </div>

              {/* Campaign Details */}
              <div className="cd-sidebar-card">
                <div className="cd-sidebar-card-title">CAMPAIGN DETAILS</div>
                <div className="cd-details-grid">
                  <span className="cd-detail-label">Owner</span>
                  <span className="cd-detail-value">
                    {notifyOwner ? (
                      <><span className="cd-avatar">{initials(notifyOwner.groupName)}</span>{notifyOwner.groupName}</>
                    ) : '—'}
                  </span>
                  <span className="cd-detail-label">Resolver</span>
                  <span className="cd-detail-value">{notifyResolver?.groupName ?? '—'}</span>
                  <span className="cd-detail-label">Due Date</span>
                  <span className="cd-detail-value">{formatDate(s.dueAt)}</span>
                  <span className="cd-detail-label">CVE(s)</span>
                  <span className="cd-detail-value cd-detail-value--mono">{cveLabel || '—'}</span>
                  <span className="cd-detail-label">Evidence</span>
                  <span className={`cd-detail-value${s.resolvedFindings > 0 && s.resolvedFindings < s.totalFindings ? ' cd-evidence-partial' : ''}`}>
                    {s.resolvedFindings === 0 ? 'None' : s.resolvedFindings === s.totalFindings ? 'Complete' : 'Partial'}
                  </span>
                </div>
              </div>

              {/* Exceptions mini-list */}
              {detail.exceptions.length > 0 && (
                <div className="cd-sidebar-card">
                  <div className="cd-sidebar-card-header">
                    <span className="cd-sidebar-card-title cd-exceptions-title">EXCEPTIONS ({detail.exceptions.length})</span>
                    <button type="button" className="cd-view-all" onClick={() => setTab('exceptions')}>View all</button>
                  </div>
                  <div className="cd-exceptions-list">
                    {detail.exceptions.slice(0, 3).map((ex) => (
                      <div key={ex.id} className="cd-exception-item">
                        <strong>{ex.assetName || ex.findingDisplayId || ex.title}</strong>
                        <span>{ex.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Advisories */}
              <div className="cd-sidebar-card">
                <div className="cd-sidebar-card-header">
                  <button
                    type="button"
                    className="cd-sidebar-collapse-btn"
                    onClick={() => setAdvisoriesCollapsed((c) => !c)}
                    title={advisoriesCollapsed ? 'Expand' : 'Collapse'}
                  >
                    <span className={`cd-sidebar-chevron${advisoriesCollapsed ? ' collapsed' : ''}`}>›</span>
                  </button>
                  <div>
                    <span className="cd-sidebar-card-title">ADVISORIES</span>
                    {advisoriesFetchedAt && (
                      <div className="cd-adv-fetched-at">
                        {new Date(advisoriesFetchedAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </div>
                    )}
                  </div>
                  <div className="cd-sidebar-card-actions">
                    <button
                      type="button"
                      className="cd-sidebar-icon-btn"
                      disabled={advisoriesLoading}
                      title={advisoriesLoading ? 'Fetching…' : advisories ? 'Refresh advisories' : 'Fetch advisories'}
                      onClick={() => void fetchAdvisories()}
                    >
                      {advisoriesLoading ? '…' : '↻'}
                    </button>
                  </div>
                </div>

                {!advisoriesCollapsed && (
                  <>
                    {advisoriesError && (
                      <div className="cd-adv-error">{advisoriesError}</div>
                    )}

                    {!advisories && !advisoriesLoading && !advisoriesError && (
                      <div className="cd-adv-empty">
                        Click ↻ to pull critical advisories for {s.cveIds.length > 0 ? s.cveIds.join(', ') : 'attached CVEs'}.
                      </div>
                    )}

                    {advisories && (
                      <div className="cd-adv-list">
                        {advisories.map((adv, i) => (
                          <div key={i} className="cd-adv-item">
                            <div className="cd-adv-item-header">
                              <span className={`cd-adv-sev cd-adv-sev--${(adv.severity ?? 'low').toLowerCase()}`}>
                                {adv.severity}
                              </span>
                              <span className="cd-adv-type">{adv.type}</span>
                              <span className="cd-adv-cve mono">{adv.cveId}</span>
                            </div>
                            <div className="cd-adv-title">{adv.title}</div>
                            <div className="cd-adv-summary">{adv.summary}</div>
                            {adv.publishedDate && adv.publishedDate !== 'null' && (
                              <div className="cd-adv-date">{adv.publishedDate}</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>

              {/* Notify groups */}
              {detail.notifyGroups.length > 0 && (
                <div className="cd-sidebar-card">
                  <div className="cd-sidebar-card-header">
                    <button
                      type="button"
                      className="cd-sidebar-collapse-btn"
                      onClick={() => setNotifyCollapsed((c) => !c)}
                      title={notifyCollapsed ? 'Expand' : 'Collapse'}
                    >
                      <span className={`cd-sidebar-chevron${notifyCollapsed ? ' collapsed' : ''}`}>›</span>
                    </button>
                    <span className="cd-sidebar-card-title">NOTIFY ({detail.notifyGroups.length})</span>
                    <div className="cd-sidebar-card-actions">
                      <button
                        type="button"
                        className="cd-sidebar-icon-btn"
                        title="Compose notification"
                        onClick={() => setShowNotify(true)}
                      >
                        ✉
                      </button>
                    </div>
                  </div>
                  {!notifyCollapsed && (
                    <div className="cd-notify-list">
                      {detail.notifyGroups.map((g) => (
                        <div key={g.id} className="cd-notify-row">
                          <span className="cd-avatar">{initials(g.groupName)}</span>
                          <div className="cd-notify-info">
                            <strong>{g.groupName}</strong>
                            {g.roleLabel && <span className="cd-notify-role">{g.roleLabel}</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'products' && (
          <div className="cd-tab-body">
            <div className="cd-tab-toolbar">
              <span className="cd-tab-toolbar-count">
                {productRows.length + (detail.softwareItems ?? []).length} software item{productRows.length + (detail.softwareItems ?? []).length !== 1 ? 's' : ''}
              </span>
              <button type="button" className="btn btn-primary" style={{ fontSize: 13, padding: '6px 14px' }}
                onClick={() => setShowAddSoftware(true)}>
                + Add Software
              </button>
            </div>
            <table className="data-table cd-findings-table">
              <thead>
                <tr>
                  <th>PACKAGE / SOFTWARE</th>
                  <th>AFFECTED ASSETS</th>
                  <th>FINDINGS</th>
                  <th>RESOLVED</th>
                  <th>MAX SEVERITY</th>
                  <th>% DONE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {productRows.map((pr) => {
                  const pctDone = pr.total > 0 ? Math.round((pr.resolved / pr.total) * 100) : 0;
                  return (
                    <tr key={pr.name} style={{ cursor: 'pointer' }} onClick={() => navigate(pathForInventoryViewWithSearch('software-identities', { query: pr.name }))}>
                      <td>
                        <strong style={{ fontSize: 13, color: 'var(--accent)' }}>{pr.name}</strong>
                      </td>
                      <td style={{ fontSize: 13 }}>{pr.assets.size}</td>
                      <td style={{ fontSize: 13 }}>{pr.total}</td>
                      <td style={{ fontSize: 13, color: '#21d07a' }}>{pr.resolved}</td>
                      <td>
                        {pr.maxSev
                          ? <span className={sevPill(pr.maxSev)}>{pr.maxSev}</span>
                          : <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span>}
                      </td>
                      <td>
                        <div className="cd-prod-progress">
                          <div className="cd-prod-bar">
                            <div className="cd-prod-bar-fill" style={{ width: `${pctDone}%` }} />
                          </div>
                          <span className="cd-prod-pct">{pctDone}%</span>
                        </div>
                      </td>
                      <td/>
                    </tr>
                  );
                })}
                {(detail.softwareItems ?? []).map((sw) => (
                  <tr key={sw.id} style={{ cursor: 'pointer' }} onClick={() => navigate(pathForSoftwareIdentityDetail(sw.id))}>
                    <td>
                      <div>
                        <strong style={{ fontSize: 13, color: 'var(--accent)' }}>{sw.displayName}</strong>
                        {sw.vendor && <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{sw.vendor}</div>}
                      </div>
                    </td>
                    <td style={{ fontSize: 13 }}>{sw.assetCount}</td>
                    <td style={{ fontSize: 13 }}>{sw.openFindingCount}</td>
                    <td style={{ fontSize: 13, color: '#21d07a' }}>—</td>
                    <td><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span></td>
                    <td><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span></td>
                    <td>
                      <button type="button" className="cd-delete-btn" title="Remove" onClick={(e) => { e.stopPropagation(); deleteSoftwareItem(sw.id); }}>✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {productRows.length === 0 && (detail.softwareItems ?? []).length === 0 && (
              <div className="cd-empty">No findings data yet — impacted products will appear once findings are generated.</div>
            )}
          </div>
        )}

        {tab === 'assets' && (
          <div className="cd-tab-body">
            <div className="cd-tab-toolbar">
              <span className="cd-tab-toolbar-count">{detail.assets.length} assets in scope</span>
              <button type="button" className="btn btn-primary" style={{ fontSize: 13, padding: '6px 14px' }}
                onClick={() => setShowAddAssets(true)}>
                + Add Assets
              </button>
            </div>
            <table className="data-table cd-assets-table">
              <thead>
                <tr>
                  <th>ASSET / CI</th>
                  <th>SUPPORT GROUP</th>
                  <th>OWNER</th>
                  <th>OPEN</th>
                  <th>RESOLVED</th>
                  <th>PRIORITY</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {detail.assets.map((a) => {
                  const assetFindings = detail.findings.filter(
                    (f) => f.assetIdentifier === a.assetIdentifier || f.assetName === a.assetName,
                  );
                  const maxSev = assetFindings.find((f) => f.severity)?.severity;
                  const ownerGroup = assetFindings.find((f) => f.ownerGroup)?.ownerGroup;
                  return (
                    <tr
                      key={`${a.assetIdentifier}-${a.assetName}`}
                      style={{ cursor: a.assetId ? 'pointer' : undefined }}
                      onClick={() => a.assetId && navigate(pathForInventoryHostAsset(a.assetId))}
                    >
                      <td>
                        <div className="cd-asset-cell">
                          <strong className="cd-asset-name">{a.assetName || a.assetIdentifier || 'Asset'}</strong>
                          {a.assetIdentifier && (
                            <span className="cd-asset-ci mono">{a.assetIdentifier}</span>
                          )}
                          <span className="cd-asset-unassigned-badge">
                            {a.supportGroup || 'Unassigned'}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: 13 }}>{a.supportGroup || '—'}</td>
                      <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{ownerGroup || '—'}</td>
                      <td style={{ fontSize: 13 }}>{a.openFindings}</td>
                      <td style={{ fontSize: 13, color: '#21d07a' }}>{a.resolvedFindings}</td>
                      <td>
                        {maxSev
                          ? <span className={sevPill(maxSev)}>{maxSev}</span>
                          : <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span>}
                      </td>
                      <td>
                        <button type="button" className="cd-delete-btn" title="Remove asset"
                          onClick={(e) => { e.stopPropagation(); deleteAsset(a.assetIdentifier, a.assetName); }}>✕</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {detail.assets.length === 0 && <div className="cd-empty">No assets scoped yet.</div>}
          </div>
        )}

        {tab === 'findings' && (
          <div className="cd-tab-body">
            <table className="data-table cd-findings-table">
              <thead>
                <tr>
                  <th>FINDING ID</th>
                  <th>CVE ID</th>
                  <th>ASSET</th>
                  <th>PACKAGE</th>
                  <th>SEVERITY</th>
                  <th>STATUS</th>
                  <th>OWNER GROUP</th>
                  <th>DUE</th>
                </tr>
              </thead>
              <tbody>
                {activeFindings.map((f) => {
                  const cveId = f.vulnerabilityId ?? detail.summary.cveIds[0] ?? null;
                  return (
                    <tr
                      key={`${f.displayId}-${f.assetIdentifier}`}
                      style={{ cursor: f.findingId && f.displayId ? 'pointer' : undefined }}
                      onClick={() => {
                        if (!f.findingId || !f.displayId) return;
                        void api.getFinding(f.findingId).then((finding: Finding) => {
                          navigate(pathForFindingDetail(f.displayId!), { state: { finding } });
                        });
                      }}
                    >
                      <td>
                        <span className="cd-finding-id-link mono">{f.displayId || '—'}</span>
                      </td>
                      <td onClick={(e) => { if (cveId) { e.stopPropagation(); navigate(pathForVulnRepoView('org-cves', cveId)); } }}>
                        <span className="mono" style={{ fontSize: 12, color: 'var(--accent)', cursor: cveId ? 'pointer' : undefined }}>
                          {cveId || '—'}
                        </span>
                      </td>
                      <td>
                        <div>
                          <strong style={{ fontSize: 13 }}>
                            {f.assetName || f.assetIdentifier || '—'}
                          </strong>
                          {f.assetIdentifier && (
                            <div className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                              {f.assetIdentifier}
                            </div>
                          )}
                        </div>
                      </td>
                      <td style={{ fontSize: 13 }}>{f.packageName || '—'}</td>
                      <td>
                        {f.severity
                          ? <span className={sevPill(f.severity)}>{f.severity}</span>
                          : <span style={{ color: 'var(--text-secondary)' }}>—</span>}
                      </td>
                      <td>
                        <span className={statusPill(f.status)}>{f.status || '—'}</span>
                      </td>
                      <td style={{ fontSize: 13 }}>{f.ownerGroup || 'Unassigned'}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        {formatDate(f.dueAt)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {activeFindings.length === 0 && <div className="cd-empty">No findings tracked yet.</div>}
          </div>
        )}

        {tab === 'exceptions' && (
          <div className="cd-tab-body">
            <table className="data-table cd-findings-table">
              <thead>
                <tr>
                  <th>FINDING / ASSET</th>
                  <th>PACKAGE</th>
                  <th>EXCEPTION TITLE</th>
                  <th>REASON</th>
                  <th>STATUS</th>
                  <th>REQUESTED BY</th>
                  <th>DUE</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {detail.exceptions.map((ex) => {
                  const linked = detail.findings.find((f) => f.displayId === ex.findingDisplayId);
                  const exStatus = ex.status === 'APPROVED' ? 'active' : ex.status === 'REJECTED' ? 'blocked' : 'review';
                  return (
                    <tr key={ex.id}>
                      <td>
                        <div>
                          {ex.findingDisplayId && (
                            <span className="cd-finding-id-link mono" style={{ display: 'block', marginBottom: 2 }}>
                              {ex.findingDisplayId}
                            </span>
                          )}
                          <span style={{ fontSize: 13 }}>
                            {ex.assetName || linked?.assetName || '—'}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: 13 }}>
                        {linked?.packageName || ex.packageName || '—'}
                      </td>
                      <td style={{ fontSize: 13, fontWeight: 600 }}>{ex.title}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 200 }}>{ex.reason}</td>
                      <td>
                        <span className={`campaign-status-badge ${exStatus}`}>
                          {ex.status.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {ex.requestedBy || '—'}
                        <div style={{ fontSize: 11, marginTop: 2 }}>{formatDate(ex.requestedAt)}</div>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        {ex.decisionDueAt ? formatDate(ex.decisionDueAt) : '—'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ padding: '3px 10px', fontSize: 12 }}
                            disabled={exceptionStatusBusy === ex.id + 'APPROVED' || ex.status === 'APPROVED'}
                            onClick={() => void updateExceptionStatus(ex.id, 'APPROVED')}
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ padding: '3px 10px', fontSize: 12 }}
                            disabled={exceptionStatusBusy === ex.id + 'REJECTED' || ex.status === 'REJECTED'}
                            onClick={() => void updateExceptionStatus(ex.id, 'REJECTED')}
                          >
                            Reject
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {detail.exceptions.length === 0 && suppressedFindings.length === 0 && (
              <div className="cd-empty">No exceptions recorded for this campaign.</div>
            )}

            {suppressedFindings.length > 0 && (
              <>
                <div className="cd-group-section-label" style={{ margin: '20px 0 8px' }}>
                  SUPPRESSED / DEFERRED FINDINGS ({suppressedFindings.length})
                </div>
                <table className="data-table cd-findings-table">
                  <thead>
                    <tr>
                      <th>FINDING ID</th>
                      <th>CVE ID</th>
                      <th>ASSET</th>
                      <th>PACKAGE</th>
                      <th>SEVERITY</th>
                      <th>STATUS</th>
                      <th>DUE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {suppressedFindings.map((f) => {
                      const cveId = f.vulnerabilityId ?? detail.summary.cveIds[0] ?? null;
                      return (
                        <tr
                          key={`sup-${f.displayId}-${f.assetIdentifier}`}
                          style={{ cursor: f.findingId && f.displayId ? 'pointer' : undefined, opacity: 0.75 }}
                          onClick={() => {
                            if (!f.findingId || !f.displayId) return;
                            void api.getFinding(f.findingId).then((finding: Finding) => {
                              navigate(pathForFindingDetail(f.displayId!), { state: { finding } });
                            });
                          }}
                        >
                          <td>
                            <span className="cd-finding-id-link mono">{f.displayId || '—'}</span>
                          </td>
                          <td onClick={(e) => { if (cveId) { e.stopPropagation(); navigate(pathForVulnRepoView('org-cves', cveId)); } }}>
                            <span className="mono" style={{ fontSize: 12, color: 'var(--accent)', cursor: cveId ? 'pointer' : undefined }}>
                              {cveId || '—'}
                            </span>
                          </td>
                          <td>
                            <strong style={{ fontSize: 13 }}>{f.assetName || f.assetIdentifier || '—'}</strong>
                          </td>
                          <td style={{ fontSize: 13 }}>{f.packageName || '—'}</td>
                          <td>
                            {f.severity
                              ? <span className={sevPill(f.severity)}>{f.severity}</span>
                              : <span style={{ color: 'var(--text-secondary)' }}>—</span>}
                          </td>
                          <td>
                            <span className={statusPill(f.status)}>{f.status || '—'}</span>
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                            {formatDate(f.dueAt)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}

        {tab === 'evidence' && (() => {
          // Deduplicate: one row per unique CVE ID
          const seenCves = new Set<string>();
          const cveRows = s.cveIds.map((cveId) => {
            const rows = detail.evidence.filter((r) => r.cveId === cveId);
            const vuln = detail.vulnerabilities.find((v) => v.externalId === cveId);
            const sev = rows[0]?.severity ?? vuln?.severity ?? null;
            const resolvedCount = rows.filter((r) => r.status === 'RESOLVED' || r.status === 'CLOSED').length;
            const totalCount = rows.length;
            return { cveId, sev, resolvedCount, totalCount, rows };
          }).filter(({ cveId }) => {
            if (seenCves.has(cveId)) return false;
            seenCves.add(cveId);
            return true;
          });
          // Fallback: if no evidence rows yet, still show the CVEs from the campaign
          const displayRows = cveRows.length > 0 ? cveRows : s.cveIds.map((cveId) => {
            const vuln = detail.vulnerabilities.find((v) => v.externalId === cveId);
            return { cveId, sev: vuln?.severity ?? null, resolvedCount: 0, totalCount: 0, rows: [] };
          });
          return (
            <div className="cd-tab-body">
              <div className="cd-tab-toolbar">
                <span className="cd-tab-toolbar-count">{displayRows.length} CVE{displayRows.length !== 1 ? 's' : ''} tracked</span>
                <button type="button" className="btn btn-primary" style={{ fontSize: 13, padding: '6px 14px' }}
                  onClick={() => setShowAddCve(true)}>
                  + Add CVE
                </button>
              </div>
              <table className="data-table cd-findings-table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>SEVERITY</th>
                    <th>FINDINGS</th>
                    <th>RESOLVED</th>
                    <th>STATUS</th>
                    <th>DUE</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {displayRows.map(({ cveId, sev, resolvedCount, totalCount }) => {
                    const pctDone = totalCount > 0 ? Math.round((resolvedCount / totalCount) * 100) : 0;
                    const evStatus = resolvedCount === totalCount && totalCount > 0 ? 'RESOLVED' : 'OPEN';
                    return (
                      <tr key={cveId} style={{ cursor: 'pointer' }} onClick={() => navigate(pathForVulnRepoView('org-cves', cveId))}>
                        <td>
                          <span className="mono" style={{ fontSize: 13, color: 'var(--accent)', fontWeight: 700 }}>
                            {cveId}
                          </span>
                        </td>
                        <td>
                          {sev
                            ? <span className={sevPill(sev)}>{sev}</span>
                            : <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span>}
                        </td>
                        <td style={{ fontSize: 13 }}>{totalCount}</td>
                        <td style={{ fontSize: 13, color: '#21d07a' }}>{resolvedCount}</td>
                        <td>
                          <span className={statusPill(evStatus)}>{evStatus}</span>
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                          {pctDone}% · {formatDate(s.dueAt)}
                        </td>
                        <td>
                          <button type="button" className="cd-delete-btn" title="Remove CVE"
                            onClick={(e) => { e.stopPropagation(); deleteCve(cveId); }}>✕</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {displayRows.length === 0 && (
                <div className="cd-empty">No CVEs linked to this campaign.</div>
              )}
            </div>
          );
        })()}

        {tab === 'activity' && (() => {
          // Merge activities and notes sorted newest-first so notes appear inline
          type FeedItem =
            | { kind: 'activity'; id: string; body: string; actor: string; ts: string }
            | { kind: 'note'; id: string; body: string; author: string; ts: string };

          const feed: FeedItem[] = [
            ...detail.activity.map((ev) => ({
              kind: 'activity' as const,
              id: ev.id,
              body: ev.body,
              actor: ev.actor,
              ts: ev.createdAt,
            })),
            ...detail.notes.map((n) => ({
              kind: 'note' as const,
              id: n.id,
              body: n.body,
              author: n.author,
              ts: n.createdAt,
            })),
          ].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

          return (
            <div className="cd-tab-body">
              <div className="cd-note-compose">
                <textarea
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  placeholder="Add a note for resolvers and stakeholders…"
                />
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={savingNote || !noteDraft.trim()}
                  onClick={() => void submitNote()}
                >
                  {savingNote ? 'Saving…' : 'Add Note'}
                </button>
              </div>
              <div className="cd-activity-list">
                {feed.map((item) => (
                  <div key={`${item.kind}-${item.id}`} className="cd-activity-row">
                    <div className={`cd-activity-dot ${item.kind === 'note' ? 'note' : ''}`} />
                    <div style={{ flex: 1 }}>
                      {item.kind === 'note' ? (
                        <>
                          <div className="cd-note-bubble">{item.body}</div>
                          <span className="muted" style={{ fontSize: 12 }}>
                            {item.author} · {formatDate(item.ts)}
                          </span>
                        </>
                      ) : (
                        <>
                          <p style={{ margin: '0 0 3px', fontSize: 13 }}>{item.body}</p>
                          <span className="muted" style={{ fontSize: 12 }}>
                            {item.actor} · {formatDate(item.ts)}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                ))}
                {feed.length === 0 && (
                  <div className="cd-empty">No activity yet.</div>
                )}
              </div>
            </div>
          );
        })()}
      </div>

      {/* ── Add Assets modal ─────────────────────────────────────────── */}
      {showAddAssets && (() => {
        // Search tab computed values
        const q = assetSearch.toLowerCase();
        const filtered = availableAssets.filter(
          (a) => a.name.toLowerCase().includes(q) || a.identifier.toLowerCase().includes(q) || (a.ownerTeam ?? '').toLowerCase().includes(q),
        );
        const totalPages = Math.max(1, Math.ceil(filtered.length / ADD_ASSETS_PAGE_SIZE));
        const safePage = Math.min(assetPage, totalPages - 1);
        const pageAssets = filtered.slice(safePage * ADD_ASSETS_PAGE_SIZE, (safePage + 1) * ADD_ASSETS_PAGE_SIZE);
        const allPageSelected = pageAssets.length > 0 && pageAssets.every((a) => selectedAssetIds.has(a.id));

        // Unique asset types for By Class tab
        const uniqueTypes = Array.from(new Set(availableAssets.map((a) => a.type).filter(Boolean))).sort();

        // Preview count for footer
        const previewCount = resolveAssetsToAdd().length;

        // Footer label
        const addLabel = previewCount > 0 ? `Add ${previewCount} Asset${previewCount !== 1 ? 's' : ''}` : 'Add Assets';

        return (
          <div className="fd3-modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) closeAddAssets(); }}>
            <div className="fd3-modal cd-asset-picker-modal">
              <div className="fd3-modal-header">
                <span>Add Assets to Campaign</span>
                <button className="fd3-modal-close" onClick={closeAddAssets}>✕</button>
              </div>

              {/* Tab selector */}
              <div className="cd-asset-tab-bar">
                {(['search', 'tag', 'class'] as AssetAddTab[]).map((t) => (
                  <button key={t} type="button"
                    className={`cd-asset-tab${addAssetsTab === t ? ' active' : ''}`}
                    onClick={() => { setAddAssetsTab(t); setAddAssetsError(''); }}>
                    {t === 'search' ? 'Search & Select' : t === 'tag' ? 'By Tag' : 'By Asset Type'}
                  </button>
                ))}
              </div>

              <div className="fd3-modal-body" style={{ padding: '14px 20px' }}>
                {addAssetsError && <div className="notice error" style={{ marginBottom: 10 }}>{addAssetsError}</div>}

                {/* ── Search & Select tab ── */}
                {addAssetsTab === 'search' && (
                  <>
                    <div className="cd-asset-search-wrap">
                      <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                        <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                      </svg>
                      <input
                        className="cd-asset-search-input"
                        placeholder="Search by name, CI identifier, or team…"
                        value={assetSearch}
                        onChange={(e) => { setAssetSearch(e.target.value); setAssetPage(0); }}
                        autoFocus
                      />
                      {assetSearch && (
                        <button className="cd-asset-search-clear" onClick={() => { setAssetSearch(''); setAssetPage(0); }}>✕</button>
                      )}
                    </div>
                    <div className="cd-asset-list">
                      {assetsLoading && <div className="cd-asset-loading">Loading assets…</div>}
                      {!assetsLoading && filtered.length === 0 && (
                        <div className="cd-asset-loading">{assetSearch ? 'No assets match your search.' : 'No assets found in inventory.'}</div>
                      )}
                      {!assetsLoading && pageAssets.length > 0 && (
                        <>
                          <div className="cd-asset-row cd-asset-row--header">
                            <label className="cd-asset-check-label">
                              <input type="checkbox" checked={allPageSelected}
                                onChange={() => {
                                  setSelectedAssetIds((prev) => {
                                    const next = new Set(prev);
                                    if (allPageSelected) pageAssets.forEach((a) => next.delete(a.id));
                                    else pageAssets.forEach((a) => next.add(a.id));
                                    return next;
                                  });
                                }}
                              />
                              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                                Select page
                              </span>
                            </label>
                            <span className="cd-asset-col-head">TYPE</span>
                            <span className="cd-asset-col-head">ENV</span>
                            <span className="cd-asset-col-head">TEAM</span>
                          </div>
                          {pageAssets.map((a) => (
                            <label key={a.id} className={`cd-asset-row${selectedAssetIds.has(a.id) ? ' cd-asset-row--selected' : ''}`}>
                              <input type="checkbox" checked={selectedAssetIds.has(a.id)} onChange={() => toggleAssetId(a.id)} />
                              <div className="cd-asset-row-name">
                                <strong>{a.name}</strong>
                                <span className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{a.identifier}</span>
                              </div>
                              <span className="cd-asset-col-cell">{a.type || '—'}</span>
                              <span className="cd-asset-col-cell">{a.environment || '—'}</span>
                              <span className="cd-asset-col-cell">{a.ownerTeam || '—'}</span>
                            </label>
                          ))}
                        </>
                      )}
                    </div>
                    {!assetsLoading && totalPages > 1 && (
                      <div className="cd-asset-pagination">
                        <button className="cd-asset-page-btn" disabled={safePage === 0} onClick={() => setAssetPage(safePage - 1)}>‹ Prev</button>
                        <span className="cd-asset-page-info">{safePage + 1} / {totalPages} · {filtered.length} assets</span>
                        <button className="cd-asset-page-btn" disabled={safePage >= totalPages - 1} onClick={() => setAssetPage(safePage + 1)}>Next ›</button>
                      </div>
                    )}
                    {!assetsLoading && filtered.length > 0 && totalPages === 1 && (
                      <div className="cd-asset-pagination">
                        <span className="cd-asset-page-info">{filtered.length} asset{filtered.length !== 1 ? 's' : ''}</span>
                      </div>
                    )}
                  </>
                )}

                {/* ── By Tag tab ── */}
                {addAssetsTab === 'tag' && (
                  <div className="cd-mode-body">
                    <p className="cd-mode-desc">
                      Enter tags to scope matching assets. Separate multiple tags with commas — any match is included.
                      <br/>Tags are matched against asset name, environment, team, type, and criticality.
                      <br/><span style={{ fontStyle: 'italic' }}>Examples: <code>prod</code>, <code>critical</code>, <code>banking</code>, <code>SAP</code></span>
                    </p>
                    <label className="cd-mode-label" style={{ marginTop: 8 }}>Tags</label>
                    <input
                      className="fpl-form-input"
                      style={{ width: '100%', boxSizing: 'border-box' }}
                      placeholder="prod, critical, us-east, SAP"
                      value={assetTagInput}
                      onChange={(e) => setAssetTagInput(e.target.value)}
                      autoFocus
                    />
                    {assetTagInput.trim() && (
                      <div className="cd-tag-preview">
                        {assetTagInput.split(',').map((t) => t.trim()).filter(Boolean).map((t) => (
                          <span key={t} className="cd-tag-chip">{t}</span>
                        ))}
                      </div>
                    )}
                    {!assetsLoading && assetTagInput.trim() && (
                      <p className="cd-mode-desc" style={{ marginTop: 8 }}>
                        {previewCount > 0
                          ? <><strong style={{ color: 'var(--accent)' }}>{previewCount}</strong> new assets would be added.</>
                          : 'No new assets match these tags (they may already be in this campaign).'}
                      </p>
                    )}
                    {assetsLoading && <p className="cd-mode-desc" style={{ marginTop: 8 }}>Loading inventory…</p>}
                  </div>
                )}

                {/* ── By Asset Type tab ── */}
                {addAssetsTab === 'class' && (
                  <div className="cd-mode-body">
                    <p className="cd-mode-desc">Select one or more asset types to add all matching assets from inventory.</p>
                    {assetsLoading
                      ? <p className="cd-mode-desc">Loading inventory…</p>
                      : uniqueTypes.length === 0
                        ? <p className="cd-mode-desc">No asset types found in inventory.</p>
                        : (
                          <div className="cd-class-grid" style={{ marginTop: 8 }}>
                            {uniqueTypes.map((cls) => {
                              const count = availableAssets.filter((a) => a.type === cls).length;
                              return (
                                <button key={cls} type="button"
                                  className={`cd-class-chip${assetClassSel.has(cls) ? ' selected' : ''}`}
                                  onClick={() => toggleAssetClass(cls)}>
                                  {assetClassSel.has(cls) && <span className="cd-class-check">✓ </span>}
                                  {cls}
                                  <span className="cd-class-count">{count}</span>
                                </button>
                              );
                            })}
                          </div>
                        )}
                    {assetClassSel.size > 0 && !assetsLoading && (
                      <p className="cd-mode-desc" style={{ marginTop: 10 }}>
                        {previewCount > 0
                          ? <><strong style={{ color: 'var(--accent)' }}>{previewCount}</strong> new assets would be added.</>
                          : 'All matching assets are already in this campaign.'}
                      </p>
                    )}
                  </div>
                )}
              </div>

              <div className="fd3-modal-footer" style={{ justifyContent: 'space-between' }}>
                <span className="cd-asset-sel-count">
                  {addAssetsTab === 'search'
                    ? selectedAssetIds.size > 0
                      ? <><strong>{selectedAssetIds.size}</strong> asset{selectedAssetIds.size !== 1 ? 's' : ''} selected</>
                      : <span style={{ color: 'var(--text-secondary)' }}>No assets selected</span>
                    : previewCount > 0
                      ? <><strong>{previewCount}</strong> asset{previewCount !== 1 ? 's' : ''} will be added</>
                      : <span style={{ color: 'var(--text-secondary)' }}>No assets matched</span>}
                </span>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-secondary" onClick={closeAddAssets}>Cancel</button>
                  <button className="btn btn-primary" disabled={previewCount === 0} onClick={submitAddAssets}>
                    {addLabel}
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ── Add CVE modal ────────────────────────────────────────────── */}
      {/* ── Add Software modal ───────────────────────────────────────── */}
      {showAddSoftware && (
        <div className="fd3-modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) closeAddSoftware(); }}>
          <div className="fd3-modal cd-asset-picker-modal">
            <div className="fd3-modal-header">
              <span>Add Software to Campaign</span>
              <button className="fd3-modal-close" onClick={closeAddSoftware}>✕</button>
            </div>
            <div className="fd3-modal-body" style={{ padding: '14px 20px' }}>
              {addSoftwareError && <div className="notice error" style={{ marginBottom: 10 }}>{addSoftwareError}</div>}
              <div className="cd-asset-search-wrap">
                <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                  <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                </svg>
                <input
                  className="cd-asset-search-input"
                  placeholder="Search software name or vendor…"
                  value={softwareSearchInput}
                  onChange={(e) => setSoftwareSearchInput(e.target.value)}
                  autoFocus
                />
                {softwareSearchInput && (
                  <button className="cd-asset-search-clear" onClick={() => setSoftwareSearchInput('')}>✕</button>
                )}
              </div>
              <div className="cd-asset-list">
                {softwareLoading && <div className="cd-asset-loading">Loading software…</div>}
                {!softwareLoading && availableSoftware.length === 0 && (
                  <div className="cd-asset-loading">{softwareSearchQuery ? 'No software matches your search.' : 'No software identities found.'}</div>
                )}
                {!softwareLoading && availableSoftware.length > 0 && (
                  <>
                    <div className="cd-cve-row cd-cve-row--header">
                      <span/>
                      <span className="cd-asset-col-head">SOFTWARE</span>
                      <span className="cd-asset-col-head">ASSETS</span>
                    </div>
                    {availableSoftware.map((sw) => {
                      const alreadyAdded = (detail?.softwareItems ?? []).some((s) => s.id === sw.id);
                      const selected = selectedSoftwareMap.has(sw.id);
                      return (
                        <label key={sw.id}
                          className={`cd-cve-row${selected ? ' cd-asset-row--selected' : ''}${alreadyAdded ? ' cd-cve-row--tracked' : ''}`}>
                          <input type="checkbox" checked={selected} disabled={alreadyAdded}
                            onChange={() => { if (!alreadyAdded) toggleSoftwareSelection(sw); }} />
                          <div>
                            <span className="cd-cve-id">{sw.displayName}</span>
                            {sw.vendor && <span style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 6 }}>{sw.vendor}</span>}
                          </div>
                          <span className="cd-asset-col-cell" style={{ fontSize: 12 }}>{sw.assetCount} assets</span>
                        </label>
                      );
                    })}
                  </>
                )}
              </div>
              {!softwareLoading && softwareTotalPages > 1 && (
                <div className="cd-asset-pagination">
                  <button className="cd-asset-page-btn" disabled={softwarePage === 0} onClick={() => setSoftwarePage(softwarePage - 1)}>‹ Prev</button>
                  <span className="cd-asset-page-info">{softwarePage + 1} / {softwareTotalPages} · {softwareTotalItems} items</span>
                  <button className="cd-asset-page-btn" disabled={softwarePage >= softwareTotalPages - 1} onClick={() => setSoftwarePage(softwarePage + 1)}>Next ›</button>
                </div>
              )}
              {!softwareLoading && softwareTotalItems > 0 && softwareTotalPages === 1 && (
                <div className="cd-asset-pagination">
                  <span className="cd-asset-page-info">{softwareTotalItems} software item{softwareTotalItems !== 1 ? 's' : ''}</span>
                </div>
              )}
            </div>
            <div className="fd3-modal-footer" style={{ justifyContent: 'space-between' }}>
              <span className="cd-asset-sel-count">
                {selectedSoftwareMap.size > 0
                  ? <><strong>{selectedSoftwareMap.size}</strong> item{selectedSoftwareMap.size !== 1 ? 's' : ''} selected</>
                  : <span style={{ color: 'var(--text-secondary)' }}>No software selected</span>}
              </span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary" onClick={closeAddSoftware}>Cancel</button>
                <button className="btn btn-primary" disabled={selectedSoftwareMap.size === 0} onClick={submitAddSoftware}>
                  {selectedSoftwareMap.size > 0 ? `Add ${selectedSoftwareMap.size} Item${selectedSoftwareMap.size !== 1 ? 's' : ''}` : 'Add Software'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showAddCve && (
        <div className="fd3-modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) closeAddCve(); }}>
          <div className="fd3-modal cd-asset-picker-modal">
            <div className="fd3-modal-header">
              <span>Add CVE to Campaign</span>
              <button className="fd3-modal-close" onClick={closeAddCve}>✕</button>
            </div>
            <div className="fd3-modal-body" style={{ padding: '14px 20px' }}>
              {addCveError && <div className="notice error" style={{ marginBottom: 10 }}>{addCveError}</div>}

              {/* Search */}
              <div className="cd-asset-search-wrap">
                <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                  <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                </svg>
                <input
                  className="cd-asset-search-input"
                  placeholder="Search CVE ID or description…"
                  value={cveSearchInput}
                  onChange={(e) => setCveSearchInput(e.target.value)}
                  autoFocus
                />
                {cveSearchInput && (
                  <button className="cd-asset-search-clear" onClick={() => setCveSearchInput('')}>✕</button>
                )}
              </div>

              {/* CVE list */}
              <div className="cd-asset-list">
                {cvesLoading && <div className="cd-asset-loading">Loading CVEs…</div>}
                {!cvesLoading && availableCves.length === 0 && (
                  <div className="cd-asset-loading">{cveSearchQuery ? 'No CVEs match your search.' : 'No org-correlated CVEs found.'}</div>
                )}
                {!cvesLoading && availableCves.length > 0 && (
                  <>
                    {/* Header */}
                    <div className="cd-cve-row cd-cve-row--header">
                      <span/>
                      <span className="cd-asset-col-head">CVE ID</span>
                      <span className="cd-asset-col-head">DESCRIPTION</span>
                    </div>
                    {availableCves.map((rec) => {
                      const tracked = (detail?.summary.cveIds ?? []).includes(rec.externalId);
                      const selected = selectedCveMap.has(rec.externalId);
                      return (
                        <label key={rec.externalId}
                          className={`cd-cve-row${selected ? ' cd-asset-row--selected' : ''}${tracked ? ' cd-cve-row--tracked' : ''}`}>
                          <input type="checkbox" checked={selected} disabled={tracked}
                            onChange={() => { if (!tracked) toggleCveSelection(rec); }} />
                          <span className="mono cd-cve-id">{rec.externalId}</span>
                          <span className="cd-cve-desc">{rec.descriptionSnippet || rec.title || '—'}</span>
                        </label>
                      );
                    })}
                  </>
                )}
              </div>

              {/* Pagination */}
              {!cvesLoading && cveTotalPages > 1 && (
                <div className="cd-asset-pagination">
                  <button className="cd-asset-page-btn" disabled={cvePage === 0} onClick={() => setCvePage(cvePage - 1)}>‹ Prev</button>
                  <span className="cd-asset-page-info">{cvePage + 1} / {cveTotalPages} · {cveTotalItems} CVEs</span>
                  <button className="cd-asset-page-btn" disabled={cvePage >= cveTotalPages - 1} onClick={() => setCvePage(cvePage + 1)}>Next ›</button>
                </div>
              )}
              {!cvesLoading && cveTotalItems > 0 && cveTotalPages === 1 && (
                <div className="cd-asset-pagination">
                  <span className="cd-asset-page-info">{cveTotalItems} CVE{cveTotalItems !== 1 ? 's' : ''}</span>
                </div>
              )}
              <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 8 }}>
                Currently tracked: <span className="mono">{cveLabel || 'none'}</span>
              </p>
            </div>
            <div className="fd3-modal-footer" style={{ justifyContent: 'space-between' }}>
              <span className="cd-asset-sel-count">
                {selectedCveMap.size > 0
                  ? <><strong>{selectedCveMap.size}</strong> CVE{selectedCveMap.size !== 1 ? 's' : ''} selected</>
                  : <span style={{ color: 'var(--text-secondary)' }}>No CVEs selected</span>}
              </span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary" onClick={closeAddCve}>Cancel</button>
                <button className="btn btn-primary" disabled={selectedCveMap.size === 0} onClick={submitAddCve}>
                  {selectedCveMap.size > 0 ? `Add ${selectedCveMap.size} CVE${selectedCveMap.size !== 1 ? 's' : ''}` : 'Add CVE'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Notify Modal ─────────────────────────────────────────────────── */}
      {showNotify && (
        <div className="cd-notify-overlay" role="presentation" onClick={(e) => { if (e.target === e.currentTarget) closeNotify(); }}>
          <div className="cd-notify-modal" role="dialog" aria-modal="true">
            <div className="cd-notify-modal-header">
              <span className="cd-notify-modal-title">
                <span>✉</span>
                <span>Notify Teams — {s.name}</span>
              </span>
              <button type="button" className="fd3-modal-close" onClick={closeNotify}>✕</button>
            </div>

            {notifySent ? (
              <div className="cd-notify-success">
                <div className="cd-notify-success-icon">✓</div>
                <h3>Notifications sent!</h3>
                <p>{notifyRecipients.size} group{notifyRecipients.size !== 1 ? 's' : ''} notified via email.</p>
                <button type="button" className="btn btn-primary" onClick={closeNotify}>Done</button>
              </div>
            ) : (
              <div className="cd-notify-body">
                {/* Left panel: Recipients */}
                <div className="cd-notify-left">
                  <div className="cd-notify-left-header">
                    <span className="cd-notify-left-title">Recipients</span>
                    <span className="cd-notify-left-count">{notifyRecipients.size} selected</span>
                  </div>
                  <div className="cd-notify-filters">
                    <button type="button" className="cd-notify-filter-btn active"
                      onClick={() => setNotifyRecipients(new Set(detail.notifyGroups.map((g) => g.id)))}>
                      All teams
                    </button>
                    <button type="button" className="cd-notify-filter-btn"
                      onClick={() => setNotifyRecipients(new Set(detail.notifyGroups.slice(0, 1).map((g) => g.id)))}>
                      Impacted only
                    </button>
                    <button type="button" className="cd-notify-filter-btn"
                      onClick={() => setNotifyRecipients(new Set())}>
                      Clear
                    </button>
                  </div>
                  <div className="cd-notify-recipients-list">
                    {detail.notifyGroups.length === 0 && (
                      <div className="cd-notify-empty">No notify groups configured for this campaign.</div>
                    )}
                    {detail.notifyGroups.map((g) => (
                      <label key={g.id} className="cd-notify-recipient-row">
                        <input
                          type="checkbox"
                          checked={notifyRecipients.has(g.id)}
                          onChange={() => {
                            setNotifyRecipients((prev) => {
                              const next = new Set(prev);
                              if (next.has(g.id)) next.delete(g.id); else next.add(g.id);
                              return next;
                            });
                          }}
                        />
                        <div className="cd-notify-recipient-info">
                          <span className="cd-avatar cd-avatar--sm">{initials(g.groupName)}</span>
                          <div>
                            <div className="cd-notify-recipient-name">{g.groupName}</div>
                            {g.roleLabel && <div className="cd-notify-recipient-role">{g.roleLabel}</div>}
                            {g.groupEmail && <div className="cd-notify-recipient-email">{g.groupEmail}</div>}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Right panel: Compose */}
                <div className="cd-notify-right">
                  <div className="cd-notify-template-row">
                    <span className="cd-notify-template-label">Template</span>
                    <select
                      className="cd-notify-template-select"
                      value={notifyTemplate}
                      onChange={(e) => setNotifyTemplate(e.target.value as NotifyTemplate)}
                    >
                      {(Object.entries(NOTIFY_TEMPLATES) as [NotifyTemplate, { label: string }][]).map(([key, tpl]) => (
                        <option key={key} value={key}>{tpl.label}</option>
                      ))}
                    </select>
                  </div>

                  <div className="cd-notify-field">
                    <label className="cd-notify-field-label">Subject</label>
                    <input
                      className="cd-notify-subject-input"
                      value={notifySubject}
                      onChange={(e) => setNotifySubject(e.target.value)}
                    />
                  </div>

                  <div className="cd-notify-field">
                    <label className="cd-notify-field-label">Message</label>
                    <textarea
                      ref={notifyBodyRef}
                      className="cd-notify-body-textarea"
                      value={notifyBody}
                      onChange={(e) => setNotifyBody(e.target.value)}
                      rows={10}
                    />
                  </div>

                  <div className="cd-notify-vars-row">
                    <span className="cd-notify-vars-label">Insert variable:</span>
                    {NOTIFY_VARIABLES.map((v) => (
                      <button key={v} type="button" className="cd-notify-var-chip" onClick={() => insertVariable(v)}>
                        {v}
                      </button>
                    ))}
                  </div>

                  <div className="cd-notify-send-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={notifyRecipients.size === 0}
                      onClick={() => setNotifySent(true)}
                    >
                      {notifyRecipients.size > 0
                        ? `Send email to ${notifyRecipients.size} group${notifyRecipients.size !== 1 ? 's' : ''}`
                        : 'Select recipients to send'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
