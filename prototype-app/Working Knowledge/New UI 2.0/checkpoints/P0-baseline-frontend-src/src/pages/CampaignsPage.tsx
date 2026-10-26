import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import type { TenantMember } from '../features/admin/types';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { Asset } from '../features/inventory/api-types';
import type { SoftwareIdentitySummary } from '../features/software-identities/types';
import type {
  CampaignCreateRequest,
  CampaignStatus,
  CampaignSummary,
} from '../features/campaigns/types';

type StatusTab = {
  label: string;
  value: CampaignStatus | 'ALL';
};

type ScopeMode = 'cves' | 'software' | 'assets';
type NotifyTemplate = 'exception_followup' | 'escalation' | 'nearing_due_date' | 'new_security_campaign';

const WIZARD_NOTIFY_TEMPLATES: Record<NotifyTemplate, { label: string; subject: string; body: string }> = {
  exception_followup: {
    label: 'Exception Follow-up',
    subject: 'Exception Request Update — Remediation Campaign',
    body: 'Hi {{owner_name}},\n\nThis is a follow-up regarding an open exception request for this remediation campaign.\n\n• Affected assets: {{asset_count}}\n• Exception due date: {{due_date}}\n• Severity: {{severity}}\n\nThe exception is currently pending review. Please ensure it is approved or rejected promptly to avoid delays.\n\nThank you,\nSecurity Operations',
  },
  escalation: {
    label: 'Escalation',
    subject: 'ESCALATION: Remediation Overdue — Immediate Attention Required',
    body: 'Hi {{owner_name}},\n\nThis is an escalation notice for an overdue remediation campaign. Immediate attention is required.\n\n• Affected assets: {{asset_count}}\n• Overdue since: {{due_date}}\n• Severity: {{severity}}\n\nThe remediation deadline has passed and affected systems remain unpatched. Leadership has been notified.\n\nPlease provide an updated remediation plan within 24 hours.\n\nThank you,\nSecurity Operations',
  },
  nearing_due_date: {
    label: 'Nearing Due Date',
    subject: 'Action Required: Remediation Due {{due_date}}',
    body: 'Hi {{owner_name}},\n\nThis is a reminder that the remediation deadline is approaching.\n\n• Affected assets: {{asset_count}}\n• Severity: {{severity}}\n• Due date: {{due_date}}\n\nPlease ensure all affected systems are remediated before the due date to avoid an SLA breach.\n\nIf you require additional time, please submit an exception request as soon as possible.\n\nThank you,\nSecurity Operations',
  },
  new_security_campaign: {
    label: 'Attention Required: New Security Campaign',
    subject: 'Attention Required: New Security Campaign Launched',
    body: 'Hi {{owner_name}},\n\nA new security remediation campaign has been launched that requires your immediate attention.\n\n• Affected assets: {{asset_count}}\n• Severity: {{severity}}\n• Target due date: {{due_date}}\n\nPlease review the campaign details and begin remediation of affected systems as soon as possible.\n\nEarly action reduces risk exposure and helps your team meet the remediation SLA.\n\nThank you,\nSecurity Operations',
  },
};

const WIZARD_NOTIFY_VARIABLES = ['{{owner_name}}', '{{asset_count}}', '{{due_date}}', '{{severity}}'] as const;

type WizardForm = {
  name: string;
  summary: string;
  dueDate: string;
  launchNote: string;
  watchlistTriggerPolicy: 'ALL_EVENTS' | 'STATUS_CHANGES' | 'NOTES_ONLY' | 'CLOSURE_RISK';
  scopeMode: ScopeMode;
  selectedCves: string[];
  selectedSoftwareIds: string[];
  selectedAssetIds: string[];
  selectedGroups: string[];
  selectedWatchlistIds: string[];
};

const STATUS_TABS: StatusTab[] = [
  { label: 'All Campaigns', value: 'ALL' },
  { label: 'Active', value: 'ACTIVE' },
  { label: 'Paused', value: 'PAUSED' },
  { label: 'Blocked', value: 'BLOCKED' },
  { label: 'Closed', value: 'CLOSED' },
  { label: 'Draft', value: 'DRAFT' },
];

const WIZARD_STEPS = ['Basics', 'Scope', 'Watchlist', 'Launch'] as const;

const SCOPE_TABS: { key: ScopeMode; label: string }[] = [
  { key: 'cves', label: 'CVEs' },
  { key: 'software', label: 'Software' },
  { key: 'assets', label: 'Assets' },
];

function statusBadgeClass(status: CampaignStatus): string {
  if (status === 'ACTIVE') return 'campaign-status-badge active';
  if (status === 'PAUSED') return 'campaign-status-badge paused';
  if (status === 'BLOCKED') return 'campaign-status-badge blocked';
  if (status === 'CLOSED' || status === 'CANCELLED') return 'campaign-status-badge closed';
  if (status === 'IN_REVIEW') return 'campaign-status-badge review';
  return 'campaign-status-badge draft';
}

function formatStatus(status: CampaignStatus): string {
  return status.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDate(value?: string | null): string {
  if (!value) return 'TBD';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function sevPill(severity?: string | null): string {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical') return 'severity-pill severity-critical';
  if (s === 'high') return 'severity-pill severity-high';
  if (s === 'medium') return 'severity-pill severity-medium';
  return 'severity-pill severity-low';
}

function createDefaultForm(): WizardForm {
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 14);
  return {
    name: '',
    summary: '',
    dueDate: dueDate.toISOString().slice(0, 10),
    launchNote: '',
    watchlistTriggerPolicy: 'ALL_EVENTS',
    scopeMode: 'cves',
    selectedCves: [],
    selectedSoftwareIds: [],
    selectedAssetIds: [],
    selectedGroups: [],
    selectedWatchlistIds: [],
  };
}

const SCOPE_PAGE_SIZE = 10;

export function CampaignsPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = React.useState<CampaignSummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [activeTab, setActiveTab] = React.useState<StatusTab['value']>('ALL');
  const [search, setSearch] = React.useState('');

  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [wizardStep, setWizardStep] = React.useState(0);
  const [wizardForm, setWizardForm] = React.useState<WizardForm>(() => createDefaultForm());
  const [wizardBusy, setWizardBusy] = React.useState(false);
  const [wizardError, setWizardError] = React.useState<string | null>(null);
  const [notifyToast, setNotifyToast] = React.useState<{ count: number } | null>(null);
  const [showWizardNotify, setShowWizardNotify] = React.useState(false);
  const [wizardNotifyTemplate, setWizardNotifyTemplate] = React.useState<NotifyTemplate>('nearing_due_date');
  const [wizardNotifySubject, setWizardNotifySubject] = React.useState('');
  const [wizardNotifyBody, setWizardNotifyBody] = React.useState('');
  const [wizardNotifySent, setWizardNotifySent] = React.useState(false);
  const wizardNotifyBodyRef = React.useRef<HTMLTextAreaElement>(null);
  const [groupOptions, setGroupOptions] = React.useState<string[]>([]);
  const [groupSearch, setGroupSearch] = React.useState('');
  const [members, setMembers] = React.useState<TenantMember[]>([]);

  // ── CVE scope picker ──────────────────────────────────────────────────────
  const [orgCves, setOrgCves] = React.useState<OrgSpecificCveExposureRecord[]>([]);
  const [cvesLoading, setCvesLoading] = React.useState(false);
  const [cveSearchInput, setCveSearchInput] = React.useState('');
  const [cveSearchQuery, setCveSearchQuery] = React.useState('');
  const [cvePage, setCvePage] = React.useState(0);
  const [cveTotalPages, setCveTotalPages] = React.useState(1);
  const [cveTotalItems, setCveTotalItems] = React.useState(0);

  // ── Software scope picker ─────────────────────────────────────────────────
  const [softwareItems, setSoftwareItems] = React.useState<SoftwareIdentitySummary[]>([]);
  const [softwareLoading, setSoftwareLoading] = React.useState(false);
  const [softwareSearchInput, setSoftwareSearchInput] = React.useState('');
  const [softwareSearchQuery, setSoftwareSearchQuery] = React.useState('');
  const [softwarePage, setSoftwarePage] = React.useState(0);
  const [softwareTotalPages, setSoftwareTotalPages] = React.useState(1);
  const [softwareTotalItems, setSoftwareTotalItems] = React.useState(0);

  // ── Asset scope picker ────────────────────────────────────────────────────
  const [assetItems, setAssetItems] = React.useState<Asset[]>([]);
  const [assetsLoading, setAssetsLoading] = React.useState(false);
  const [assetSearchInput, setAssetSearchInput] = React.useState('');
  const [assetPage, setAssetPage] = React.useState(0);

  const loadCampaigns = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCampaigns(activeTab === 'ALL' ? undefined : activeTab);
      setCampaigns(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setCampaigns([]);
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  React.useEffect(() => {
    void loadCampaigns();
  }, [loadCampaigns]);

  // Load groups + members when wizard opens
  React.useEffect(() => {
    if (!wizardOpen) return;
    let cancelled = false;
    Promise.all([
      api.listAssignmentGroups(),
      actor?.tenantId ? api.listTenantMembers(actor.tenantId) : Promise.resolve([] as TenantMember[]),
    ])
      .then(([groups, tenantMembers]) => {
        if (cancelled) return;
        setGroupOptions(Array.from(new Set(groups)).sort((a, b) => a.localeCompare(b)));
        setMembers(tenantMembers);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setWizardError(err instanceof Error ? err.message : String(err));
      });
    return () => { cancelled = true; };
  }, [wizardOpen, actor?.tenantId]);

  // CVE search debounce
  React.useEffect(() => {
    const t = setTimeout(() => { setCveSearchQuery(cveSearchInput); setCvePage(0); }, 300);
    return () => clearTimeout(t);
  }, [cveSearchInput]);

  // Load CVEs when on scope step + CVE tab
  React.useEffect(() => {
    if (!wizardOpen || wizardStep !== 1 || wizardForm.scopeMode !== 'cves') return;
    setCvesLoading(true);
    cveWorkbenchApi.listOrgSpecificCves({ page: cvePage, size: SCOPE_PAGE_SIZE, query: cveSearchQuery || undefined })
      .then((result) => {
        setOrgCves(result.items);
        setCveTotalPages(Math.max(1, result.totalPages));
        setCveTotalItems(result.totalItems);
      })
      .catch((err: unknown) => setWizardError(err instanceof Error ? err.message : String(err)))
      .finally(() => setCvesLoading(false));
  }, [wizardOpen, wizardStep, wizardForm.scopeMode, cvePage, cveSearchQuery]);

  // Software search debounce
  React.useEffect(() => {
    const t = setTimeout(() => { setSoftwareSearchQuery(softwareSearchInput); setSoftwarePage(0); }, 300);
    return () => clearTimeout(t);
  }, [softwareSearchInput]);

  // Load software when on scope step + software tab
  React.useEffect(() => {
    if (!wizardOpen || wizardStep !== 1 || wizardForm.scopeMode !== 'software') return;
    setSoftwareLoading(true);
    api.listSoftwareIdentities({ page: softwarePage, size: SCOPE_PAGE_SIZE, query: softwareSearchQuery || undefined })
      .then((result) => {
        setSoftwareItems(result.content);
        setSoftwareTotalPages(Math.max(1, result.totalPages));
        setSoftwareTotalItems(result.totalElements);
      })
      .catch((err: unknown) => setWizardError(err instanceof Error ? err.message : String(err)))
      .finally(() => setSoftwareLoading(false));
  }, [wizardOpen, wizardStep, wizardForm.scopeMode, softwarePage, softwareSearchQuery]);

  // Load assets when on scope step + asset tab (once, client-side search/pagination)
  React.useEffect(() => {
    if (!wizardOpen || wizardStep !== 1 || wizardForm.scopeMode !== 'assets') return;
    if (assetItems.length > 0) return; // already loaded
    setAssetsLoading(true);
    api.listAssets()
      .then((assets) => setAssetItems(assets))
      .catch((err: unknown) => setWizardError(err instanceof Error ? err.message : String(err)))
      .finally(() => setAssetsLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wizardOpen, wizardStep, wizardForm.scopeMode]);

  const filteredAssets = React.useMemo(() => {
    const q = assetSearchInput.trim().toLowerCase();
    if (!q) return assetItems;
    return assetItems.filter((a) =>
      a.name.toLowerCase().includes(q) ||
      a.identifier.toLowerCase().includes(q) ||
      (a.type ?? '').toLowerCase().includes(q) ||
      (a.environment ?? '').toLowerCase().includes(q),
    );
  }, [assetItems, assetSearchInput]);

  const assetPageItems = filteredAssets.slice(assetPage * SCOPE_PAGE_SIZE, (assetPage + 1) * SCOPE_PAGE_SIZE);
  const assetTotalPages = Math.max(1, Math.ceil(filteredAssets.length / SCOPE_PAGE_SIZE));

  const filteredCampaigns = React.useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return campaigns;
    return campaigns.filter((campaign) =>
      campaign.name.toLowerCase().includes(query)
      || campaign.cveIds.some((cveId) => cveId.toLowerCase().includes(query))
      || (campaign.summary ?? '').toLowerCase().includes(query),
    );
  }, [campaigns, search]);

  const countsByTab = React.useMemo(() => {
    const counts = new Map<StatusTab['value'], number>();
    counts.set('ALL', campaigns.length);
    STATUS_TABS.forEach((tab) => {
      if (tab.value === 'ALL') return;
      counts.set(tab.value, campaigns.filter((campaign) => campaign.status === tab.value).length);
    });
    return counts;
  }, [campaigns]);

  function toggleSelection(list: string[], value: string): string[] {
    return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
  }

  // Wizard notify template effect
  React.useEffect(() => {
    if (!showWizardNotify) return;
    setWizardNotifySubject(WIZARD_NOTIFY_TEMPLATES[wizardNotifyTemplate].subject);
    setWizardNotifyBody(WIZARD_NOTIFY_TEMPLATES[wizardNotifyTemplate].body);
  }, [wizardNotifyTemplate, showWizardNotify]);

  // Open wizard notify
  function openWizardNotify(): void {
    setWizardNotifySent(false);
    setWizardNotifyTemplate('nearing_due_date');
    setWizardNotifySubject(WIZARD_NOTIFY_TEMPLATES.nearing_due_date.subject);
    setWizardNotifyBody(WIZARD_NOTIFY_TEMPLATES.nearing_due_date.body);
    setShowWizardNotify(true);
  }

  function insertWizardVariable(v: string): void {
    const el = wizardNotifyBodyRef.current;
    if (!el) { setWizardNotifyBody((prev) => `${prev} ${v}`); return; }
    const start = el.selectionStart ?? wizardNotifyBody.length;
    const end = el.selectionEnd ?? wizardNotifyBody.length;
    setWizardNotifyBody(wizardNotifyBody.slice(0, start) + v + wizardNotifyBody.slice(end));
    setTimeout(() => { el.focus(); el.setSelectionRange(start + v.length, start + v.length); }, 0);
  }

  function resetWizard(): void {
    setWizardStep(0);
    setWizardForm(createDefaultForm());
    setWizardBusy(false);
    setWizardError(null);
    // Reset picker state
    setOrgCves([]); setCvesLoading(false); setCveSearchInput(''); setCveSearchQuery(''); setCvePage(0); setCveTotalPages(1); setCveTotalItems(0);
    setSoftwareItems([]); setSoftwareLoading(false); setSoftwareSearchInput(''); setSoftwareSearchQuery(''); setSoftwarePage(0); setSoftwareTotalPages(1); setSoftwareTotalItems(0);
    setAssetItems([]); setAssetsLoading(false); setAssetSearchInput(''); setAssetPage(0);
    setShowWizardNotify(false); setWizardNotifySent(false);
  }

  function openWizard(): void {
    resetWizard();
    setWizardOpen(true);
  }

  function closeWizard(): void {
    setWizardOpen(false);
    resetWizard();
  }

  function switchScopeTab(mode: ScopeMode): void {
    setWizardForm((f) => ({ ...f, scopeMode: mode }));
    // Reset pagination/search for the new tab
    if (mode === 'cves') { setCvePage(0); setCveSearchInput(''); }
    if (mode === 'software') { setSoftwarePage(0); setSoftwareSearchInput(''); }
    if (mode === 'assets') { setAssetPage(0); setAssetSearchInput(''); }
  }

  function scopeSelectionCount(): number {
    if (wizardForm.scopeMode === 'cves') return wizardForm.selectedCves.length;
    if (wizardForm.scopeMode === 'software') return wizardForm.selectedSoftwareIds.length;
    return wizardForm.selectedAssetIds.length;
  }

  async function submitWizard(): Promise<void> {
    setWizardBusy(true);
    setWizardError(null);
    const watchlist = members
      .filter((member) => wizardForm.selectedWatchlistIds.includes(member.id))
      .map((member) => ({
        entryType: 'USER' as const,
        label: member.displayName || member.email || member.subject,
        email: member.email,
        triggerPolicy: wizardForm.watchlistTriggerPolicy,
        active: true,
      }));
    // Backend requires at least one CVE; if none selected send a placeholder CVE list from
    // whatever the org has so the record is created. Scope is always editable post-launch.
    const cveIds = wizardForm.scopeMode === 'cves' && wizardForm.selectedCves.length > 0
      ? wizardForm.selectedCves
      : wizardForm.selectedCves.length > 0 ? wizardForm.selectedCves : [];

    const payload: CampaignCreateRequest = {
      name: wizardForm.name.trim() || 'Untitled Campaign',
      summary: wizardForm.summary.trim() || null,
      cveIds,
      dueAt: wizardForm.dueDate ? new Date(`${wizardForm.dueDate}T00:00:00Z`).toISOString() : null,
      launchNote: wizardForm.launchNote.trim() || null,
      notifyGroups: wizardForm.selectedGroups.map((groupName, index) => ({
        groupName,
        roleLabel: index === 0 ? 'Owner group' : 'Resolver group',
        triggerSummary: 'Status changes, notes, closure risk',
        notificationsPaused: false,
      })),
      watchlist,
    };
    try {
      const created = await api.createCampaign(payload);
      closeWizard();
      await loadCampaigns();
      if (payload.notifyGroups && payload.notifyGroups.length > 0) {
        setNotifyToast({ count: payload.notifyGroups.length });
        setTimeout(() => setNotifyToast(null), 4500);
      }
      navigate(`/vuln-repo/campaigns/${created.summary.id}`);
    } catch (err) {
      setWizardError(err instanceof Error ? err.message : String(err));
    } finally {
      setWizardBusy(false);
    }
  }

  // Scope selection label for summary
  function scopeSummaryLabel(): string {
    const mode = wizardForm.scopeMode;
    const count = scopeSelectionCount();
    if (mode === 'cves') return `${count} CVE${count !== 1 ? 's' : ''}`;
    if (mode === 'software') return `${count} software item${count !== 1 ? 's' : ''}`;
    return `${count} asset${count !== 1 ? 's' : ''}`;
  }

  return (
    <div className="campaigns-page">
      <div className="campaigns-tab-row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {STATUS_TABS.map((tab) => (
            <button
              key={tab.value}
              type="button"
              className={activeTab === tab.value ? 'campaign-tab active' : 'campaign-tab'}
              onClick={() => setActiveTab(tab.value)}
            >
              <span>{tab.label}</span>
              <span className="campaign-tab-count">{countsByTab.get(tab.value) ?? 0}</span>
            </button>
          ))}
        </div>
        <button type="button" className="btn btn-primary" onClick={openWizard}>
          New Campaign
        </button>
      </div>

<div className="campaigns-filter-row">
        <input
          className="input"
          type="search"
          placeholder="Search campaigns, CVEs, or summary"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      {error && <div className="notice error">{error}</div>}

      <div className="campaigns-body campaigns-body--full">
        <section className="panel campaigns-list-panel campaigns-list-panel--full">
          {loading ? (
            <div className="notice">Loading campaigns...</div>
          ) : filteredCampaigns.length === 0 ? (
            <div className="campaign-empty">
              <h3>No campaigns yet</h3>
              <p>Create the first remediation campaign to turn CVE scope into an operational rollout.</p>
            </div>
          ) : (
            <table className="campaigns-table">
              <thead>
                <tr>
                  <th>Campaign</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Assets</th>
                  <th>Due</th>
                </tr>
              </thead>
              <tbody>
                {filteredCampaigns.map((campaign) => (
                  <tr
                    key={campaign.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/vuln-repo/campaigns/${campaign.id}`)}
                  >
                    <td>
                      <div className="campaign-name-cell">
                        <strong>{campaign.name}</strong>
                        <span>{campaign.cveIds.join(', ')}</span>
                      </div>
                    </td>
                    <td>
                      <span className={statusBadgeClass(campaign.status)}>{formatStatus(campaign.status)}</span>
                    </td>
                    <td>
                      <div className="campaign-progress-cell">
                        <div className="campaign-progress-bar">
                          <div style={{ width: `${campaign.completionPercent}%` }} />
                        </div>
                        <span>{campaign.completionPercent}%</span>
                      </div>
                    </td>
                    <td>{campaign.assetCount}</td>
                    <td>{formatDate(campaign.dueAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      {/* ── New Campaign Wizard ──────────────────────────────────────────── */}
      {wizardOpen && (
        <div className="campaign-modal-backdrop" role="presentation" onClick={closeWizard}>
          <section className="campaign-modal cw-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>

            {/* Header */}
            <div className="cw-header">
              <div className="cw-header-title">
                <span className="cw-header-icon">⚡</span>
                <div>
                  <h3>New Campaign</h3>
                  <p className="cw-header-sub">Define scope, notify the right teams, and launch a remediation sprint.</p>
                </div>
              </div>
              <button type="button" className="cd-delete-btn" style={{ opacity: 1, fontSize: 18, padding: '6px 10px' }} onClick={closeWizard}>✕</button>
            </div>

            {/* Step rail */}
            <div className="cw-step-rail">
              {WIZARD_STEPS.map((step, index) => (
                <React.Fragment key={step}>
                  <button
                    type="button"
                    className={`cw-step${wizardStep === index ? ' cw-step--active' : ''}${wizardStep > index ? ' cw-step--done' : ''}`}
                    onClick={() => setWizardStep(index)}
                  >
                    <span className="cw-step-num">
                      {wizardStep > index ? '✓' : index + 1}
                    </span>
                    <span className="cw-step-label">{step}</span>
                  </button>
                  {index < WIZARD_STEPS.length - 1 && (
                    <div className={`cw-step-connector${wizardStep > index ? ' cw-step-connector--done' : ''}`} />
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Body */}
            <div className="cw-body">
              {wizardError && <div className="notice error" style={{ marginBottom: 14 }}>{wizardError}</div>}

              {/* Step 1: Basics */}
              {wizardStep === 0 && (
                <div className="cw-basics-grid">
                  <div className="cw-field">
                    <label className="cw-label" htmlFor="campaign-name">Campaign Name</label>
                    <input
                      id="campaign-name"
                      className="cw-input"
                      placeholder="e.g. Log4Shell – Critical Systems Rollout"
                      value={wizardForm.name}
                      onChange={(e) => setWizardForm((f) => ({ ...f, name: e.target.value }))}
                      autoFocus
                    />
                  </div>
                  <div className="cw-field">
                    <label className="cw-label" htmlFor="campaign-due-date">Target Due Date</label>
                    <input
                      id="campaign-due-date"
                      className="cw-input"
                      type="date"
                      value={wizardForm.dueDate}
                      onChange={(e) => setWizardForm((f) => ({ ...f, dueDate: e.target.value }))}
                    />
                  </div>
                  <div className="cw-field cw-field--full">
                    <label className="cw-label" htmlFor="campaign-summary">Summary</label>
                    <textarea
                      id="campaign-summary"
                      className="cw-input cw-textarea"
                      placeholder="Brief description of the campaign goal, affected systems, and urgency…"
                      value={wizardForm.summary}
                      onChange={(e) => setWizardForm((f) => ({ ...f, summary: e.target.value }))}
                    />
                  </div>
                </div>
              )}

              {/* Step 2: Scope */}
              {wizardStep === 1 && (
                <div className="cw-scope-body">
                  {/* Scope type selector */}
                  <div className="cw-scope-type-row">
                    <span className="cw-scope-type-label">Scope this campaign by:</span>
                    <div className="cw-scope-type-tabs">
                      {SCOPE_TABS.map(({ key, label }) => (
                        <button
                          key={key}
                          type="button"
                          className={`cw-scope-type-tab${wizardForm.scopeMode === key ? ' active' : ''}`}
                          onClick={() => switchScopeTab(key)}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* CVEs tab */}
                  {wizardForm.scopeMode === 'cves' && (
                    <>
                      <div className="cd-asset-search-wrap">
                        <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                          <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                        </svg>
                        <input
                          className="cd-asset-search-input"
                          placeholder="Search CVE ID or description…"
                          value={cveSearchInput}
                          onChange={(e) => setCveSearchInput(e.target.value)}
                        />
                        {cveSearchInput && (
                          <button className="cd-asset-search-clear" onClick={() => setCveSearchInput('')}>✕</button>
                        )}
                      </div>
                      <div className="cw-scope-list">
                        {cvesLoading && <div className="cd-asset-loading">Loading CVEs…</div>}
                        {!cvesLoading && orgCves.length === 0 && (
                          <div className="cd-asset-loading">{cveSearchQuery ? 'No CVEs match.' : 'No org-correlated CVEs found.'}</div>
                        )}
                        {!cvesLoading && orgCves.length > 0 && (
                          <>
                            <div className="cd-cve-row cd-cve-row--header" style={{ gridTemplateColumns: '24px 150px 1fr 80px' }}>
                              <span />
                              <span className="cd-asset-col-head">CVE ID</span>
                              <span className="cd-asset-col-head">DESCRIPTION</span>
                              <span className="cd-asset-col-head">SEVERITY</span>
                            </div>
                            {orgCves.map((rec) => {
                              const selected = wizardForm.selectedCves.includes(rec.externalId);
                              return (
                                <label
                                  key={rec.externalId}
                                  className={`cd-cve-row${selected ? ' cd-asset-row--selected' : ''}`}
                                  style={{ gridTemplateColumns: '24px 150px 1fr 80px' }}
                                >
                                  <input type="checkbox" checked={selected}
                                    onChange={() => setWizardForm((f) => ({ ...f, selectedCves: toggleSelection(f.selectedCves, rec.externalId) }))} />
                                  <span className="mono cd-cve-id">{rec.externalId}</span>
                                  <span className="cd-cve-desc">{rec.descriptionSnippet || rec.title || '—'}</span>
                                  <span>
                                    {rec.severity
                                      ? <span className={sevPill(rec.severity)} style={{ fontSize: 10 }}>{rec.severity}</span>
                                      : <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>—</span>}
                                  </span>
                                </label>
                              );
                            })}
                          </>
                        )}
                      </div>
                      {!cvesLoading && cveTotalPages > 1 && (
                        <div className="cd-asset-pagination">
                          <button className="cd-asset-page-btn" disabled={cvePage === 0} onClick={() => setCvePage(cvePage - 1)}>‹ Prev</button>
                          <span className="cd-asset-page-info">{cvePage + 1} / {cveTotalPages} · {cveTotalItems} CVEs</span>
                          <button className="cd-asset-page-btn" disabled={cvePage >= cveTotalPages - 1} onClick={() => setCvePage(cvePage + 1)}>Next ›</button>
                        </div>
                      )}
                    </>
                  )}

                  {/* Software tab */}
                  {wizardForm.scopeMode === 'software' && (
                    <>
                      <div className="cd-asset-search-wrap">
                        <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                          <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                        </svg>
                        <input
                          className="cd-asset-search-input"
                          placeholder="Search software name or vendor…"
                          value={softwareSearchInput}
                          onChange={(e) => setSoftwareSearchInput(e.target.value)}
                        />
                        {softwareSearchInput && (
                          <button className="cd-asset-search-clear" onClick={() => setSoftwareSearchInput('')}>✕</button>
                        )}
                      </div>
                      <div className="cw-scope-list">
                        {softwareLoading && <div className="cd-asset-loading">Loading software…</div>}
                        {!softwareLoading && softwareItems.length === 0 && (
                          <div className="cd-asset-loading">{softwareSearchQuery ? 'No software matches.' : 'No software identities found.'}</div>
                        )}
                        {!softwareLoading && softwareItems.length > 0 && (
                          <>
                            <div className="cd-cve-row cd-cve-row--header" style={{ gridTemplateColumns: '24px 1fr 70px 70px' }}>
                              <span />
                              <span className="cd-asset-col-head">SOFTWARE</span>
                              <span className="cd-asset-col-head">ASSETS</span>
                              <span className="cd-asset-col-head">FINDINGS</span>
                            </div>
                            {softwareItems.map((sw) => {
                              const selected = wizardForm.selectedSoftwareIds.includes(sw.id);
                              return (
                                <label
                                  key={sw.id}
                                  className={`cd-cve-row${selected ? ' cd-asset-row--selected' : ''}`}
                                  style={{ gridTemplateColumns: '24px 1fr 70px 70px' }}
                                >
                                  <input type="checkbox" checked={selected}
                                    onChange={() => setWizardForm((f) => ({ ...f, selectedSoftwareIds: toggleSelection(f.selectedSoftwareIds, sw.id) }))} />
                                  <div>
                                    <span className="cd-cve-id" style={{ fontFamily: 'inherit' }}>{sw.displayName}</span>
                                    {sw.vendor && <span style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 6 }}>{sw.vendor}</span>}
                                  </div>
                                  <span className="cd-asset-col-cell" style={{ fontSize: 12 }}>{sw.assetCount}</span>
                                  <span className="cd-asset-col-cell" style={{ fontSize: 12 }}>{sw.openFindingCount}</span>
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
                    </>
                  )}

                  {/* Assets tab */}
                  {wizardForm.scopeMode === 'assets' && (
                    <>
                      <div className="cd-asset-search-wrap">
                        <svg className="cd-asset-search-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                          <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd"/>
                        </svg>
                        <input
                          className="cd-asset-search-input"
                          placeholder="Search asset name, identifier, or type…"
                          value={assetSearchInput}
                          onChange={(e) => { setAssetSearchInput(e.target.value); setAssetPage(0); }}
                        />
                        {assetSearchInput && (
                          <button className="cd-asset-search-clear" onClick={() => { setAssetSearchInput(''); setAssetPage(0); }}>✕</button>
                        )}
                      </div>
                      <div className="cw-scope-list">
                        {assetsLoading && <div className="cd-asset-loading">Loading assets…</div>}
                        {!assetsLoading && assetPageItems.length === 0 && (
                          <div className="cd-asset-loading">{assetSearchInput ? 'No assets match.' : 'No assets found.'}</div>
                        )}
                        {!assetsLoading && assetPageItems.length > 0 && (
                          <>
                            <div className="cd-cve-row cd-cve-row--header" style={{ gridTemplateColumns: '24px 1fr 80px 80px' }}>
                              <span />
                              <span className="cd-asset-col-head">ASSET</span>
                              <span className="cd-asset-col-head">TYPE</span>
                              <span className="cd-asset-col-head">ENV</span>
                            </div>
                            {assetPageItems.map((a) => {
                              const selected = wizardForm.selectedAssetIds.includes(a.identifier);
                              return (
                                <label
                                  key={a.id}
                                  className={`cd-cve-row${selected ? ' cd-asset-row--selected' : ''}`}
                                  style={{ gridTemplateColumns: '24px 1fr 80px 80px' }}
                                >
                                  <input type="checkbox" checked={selected}
                                    onChange={() => setWizardForm((f) => ({ ...f, selectedAssetIds: toggleSelection(f.selectedAssetIds, a.identifier) }))} />
                                  <div>
                                    <span style={{ fontSize: 13, fontWeight: 600 }}>{a.name}</span>
                                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 6 }}>{a.identifier}</span>
                                  </div>
                                  <span className="cd-asset-col-cell" style={{ fontSize: 11 }}>{a.type || '—'}</span>
                                  <span className="cd-asset-col-cell" style={{ fontSize: 11 }}>{a.environment || '—'}</span>
                                </label>
                              );
                            })}
                          </>
                        )}
                      </div>
                      {!assetsLoading && assetTotalPages > 1 && (
                        <div className="cd-asset-pagination">
                          <button className="cd-asset-page-btn" disabled={assetPage === 0} onClick={() => setAssetPage(assetPage - 1)}>‹ Prev</button>
                          <span className="cd-asset-page-info">{assetPage + 1} / {assetTotalPages} · {filteredAssets.length} assets</span>
                          <button className="cd-asset-page-btn" disabled={assetPage >= assetTotalPages - 1} onClick={() => setAssetPage(assetPage + 1)}>Next ›</button>
                        </div>
                      )}
                    </>
                  )}

                  {/* Selection count */}
                  <div className="cw-scope-sel-row">
                    {scopeSelectionCount() > 0
                      ? <span><strong>{scopeSelectionCount()}</strong> {wizardForm.scopeMode === 'cves' ? `CVE${scopeSelectionCount() !== 1 ? 's' : ''}` : wizardForm.scopeMode === 'software' ? `software item${scopeSelectionCount() !== 1 ? 's' : ''}` : `asset${scopeSelectionCount() !== 1 ? 's' : ''}`} selected</span>
                      : <span style={{ color: 'var(--text-secondary)' }}>Nothing selected yet</span>}
                  </div>
                </div>
              )}

              {/* Step 3: Watchlist */}
              {wizardStep === 2 && (
                <div className="campaign-form-columns">
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                      <h4 style={{ margin: 0 }}>Notify Groups</h4>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {wizardNotifySent && (
                          <span style={{ fontSize: 11, color: '#21d07a' }}>✓ Sent</span>
                        )}
                        <button
                          type="button"
                          className="btn"
                          style={{ fontSize: 13, background: 'var(--accent)', color: '#fff', padding: '5px 12px', borderRadius: 8, border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}
                          onClick={openWizardNotify}
                        >
                          ✉ Compose Notification
                          {wizardForm.selectedGroups.length > 0 && (
                            <span style={{ background: 'rgba(255,255,255,0.25)', borderRadius: 999, padding: '1px 6px', fontSize: 11, fontWeight: 700 }}>
                              {wizardForm.selectedGroups.length}
                            </span>
                          )}
                        </button>
                      </div>
                    </div>
                    <input
                      type="search"
                      placeholder="Search groups…"
                      value={groupSearch}
                      onChange={(e) => setGroupSearch(e.target.value)}
                      style={{ width: '100%', marginBottom: 10, padding: '6px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--input-bg, var(--panel))', color: 'var(--text-primary)', fontSize: 13 }}
                    />
                    <div className="campaign-chip-grid">
                      {groupOptions.filter((g) => g.toLowerCase().includes(groupSearch.toLowerCase())).map((group) => (
                        <button
                          key={group}
                          type="button"
                          className={wizardForm.selectedGroups.includes(group) ? 'campaign-chip active' : 'campaign-chip'}
                          onClick={() => setWizardForm((f) => ({ ...f, selectedGroups: toggleSelection(f.selectedGroups, group) }))}
                        >
                          {group}
                        </button>
                      ))}
                    </div>
                    {wizardForm.selectedGroups.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {`${wizardForm.selectedGroups.length} group${wizardForm.selectedGroups.length !== 1 ? 's' : ''} selected`}
                        </span>
                      </div>
                    )}
                  </div>
                  <div>
                    <h4>Watchlist Members</h4>
                    <label className="campaign-watchlist-policy" htmlFor="campaign-trigger-policy">
                      <span>Trigger Policy</span>
                      <select
                        id="campaign-trigger-policy"
                        value={wizardForm.watchlistTriggerPolicy}
                        onChange={(e) => setWizardForm((f) => ({ ...f, watchlistTriggerPolicy: e.target.value as WizardForm['watchlistTriggerPolicy'] }))}
                      >
                        <option value="ALL_EVENTS">All events</option>
                        <option value="STATUS_CHANGES">Status changes only</option>
                        <option value="NOTES_ONLY">Notes only</option>
                        <option value="CLOSURE_RISK">Closure risk only</option>
                      </select>
                    </label>
                    <div className="campaign-picker-grid compact">
                      {members.map((member) => {
                        const selected = wizardForm.selectedWatchlistIds.includes(member.id);
                        return (
                          <button
                            key={member.id}
                            type="button"
                            className={selected ? 'campaign-choice-card active' : 'campaign-choice-card'}
                            onClick={() => setWizardForm((f) => ({ ...f, selectedWatchlistIds: toggleSelection(f.selectedWatchlistIds, member.id) }))}
                          >
                            <strong>{member.displayName || member.email || member.subject}</strong>
                            <span>{member.role}</span>
                            <small>{member.email || 'No email on record'}</small>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {/* Step 4: Launch */}
              {wizardStep === 3 && (
                <div className="campaign-form-grid">
                  <div className="campaign-launch-summary full cw-launch-summary">
                    <h4>Launch Summary</h4>
                    <div className="cw-launch-kpis">
                      <div className="cw-launch-kpi">
                        <span className="cw-launch-kpi-val">{wizardForm.name || '—'}</span>
                        <span className="cw-launch-kpi-lbl">Campaign name</span>
                      </div>
                      <div className="cw-launch-kpi">
                        <span className="cw-launch-kpi-val">{scopeSummaryLabel()}</span>
                        <span className="cw-launch-kpi-lbl">
                          {wizardForm.scopeMode === 'cves' ? 'CVE scope' : wizardForm.scopeMode === 'software' ? 'Software scope' : 'Asset scope'}
                        </span>
                      </div>
                      <div className="cw-launch-kpi">
                        <span className="cw-launch-kpi-val">{wizardForm.selectedGroups.length}</span>
                        <span className="cw-launch-kpi-lbl">Notify groups</span>
                      </div>
                      <div className="cw-launch-kpi">
                        <span className="cw-launch-kpi-val">{wizardForm.selectedWatchlistIds.length}</span>
                        <span className="cw-launch-kpi-lbl">Watchlist members</span>
                      </div>
                      <div className="cw-launch-kpi">
                        <span className="cw-launch-kpi-val">{formatDate(wizardForm.dueDate)}</span>
                        <span className="cw-launch-kpi-lbl">Target due date</span>
                      </div>
                    </div>
                    {wizardForm.scopeMode === 'cves' && wizardForm.selectedCves.length > 0 && (
                      <div className="cw-launch-cve-chips">
                        {wizardForm.selectedCves.map((id) => (
                          <span key={id} className="cw-launch-cve-chip mono">{id}</span>
                        ))}
                      </div>
                    )}
                    {wizardForm.scopeMode !== 'cves' && (
                      <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 10 }}>
                        Software and asset scope can be managed in full from the campaign workspace after launch.
                      </p>
                    )}
                  </div>
                  <label className="full" htmlFor="campaign-launch-note">
                    <span style={{ fontSize: 13, fontWeight: 600, display: 'block', marginBottom: 6 }}>Launch Note <span style={{ fontWeight: 400, color: 'var(--text-secondary)' }}>(optional)</span></span>
                    <textarea
                      id="campaign-launch-note"
                      className="cw-input cw-textarea"
                      placeholder="Describe the urgency, context, or initial guidance for this campaign…"
                      value={wizardForm.launchNote}
                      onChange={(e) => setWizardForm((f) => ({ ...f, launchNote: e.target.value }))}
                    />
                  </label>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="cw-footer">
              {wizardStep > 0 && (
                <button type="button" className="btn btn-secondary" onClick={() => setWizardStep((s) => Math.max(0, s - 1))}>
                  Back
                </button>
              )}
              {wizardStep < WIZARD_STEPS.length - 1 ? (
                <button type="button" className="btn btn-primary" onClick={() => setWizardStep((s) => Math.min(WIZARD_STEPS.length - 1, s + 1))}>
                  Next
                </button>
              ) : (
                <button type="button" className="btn btn-primary" disabled={wizardBusy} onClick={() => void submitWizard()}>
                  {wizardBusy ? 'Launching…' : 'Launch Campaign'}
                </button>
              )}
            </div>
          </section>
        </div>
      )}

      {/* ── Wizard Notify Modal ──────────────────────────────────────────── */}
      {showWizardNotify && (
        <div className="cd-notify-overlay" role="presentation" onClick={(e) => { if (e.target === e.currentTarget) setShowWizardNotify(false); }}>
          <div className="cd-notify-modal" role="dialog" aria-modal="true">
            <div className="cd-notify-modal-header">
              <span className="cd-notify-modal-title">
                <span>✉</span>
                <span>Compose Notification — {wizardForm.selectedGroups.length} group{wizardForm.selectedGroups.length !== 1 ? 's' : ''}</span>
              </span>
              <button type="button" className="fd3-modal-close" onClick={() => setShowWizardNotify(false)}>✕</button>
            </div>

            {wizardNotifySent ? (
              <div className="cd-notify-success">
                <div className="cd-notify-success-icon">✓</div>
                <h3>Notifications sent!</h3>
                <p>{wizardForm.selectedGroups.length} group{wizardForm.selectedGroups.length !== 1 ? 's' : ''} notified via email.</p>
                <button type="button" className="btn btn-primary" onClick={() => setShowWizardNotify(false)}>Done</button>
              </div>
            ) : (
              <div className="cd-notify-body">
                {/* Left: recipients */}
                <div className="cd-notify-left">
                  <div className="cd-notify-left-header">
                    <span className="cd-notify-left-title">Recipients</span>
                    <span className="cd-notify-left-count">{wizardForm.selectedGroups.length} selected</span>
                  </div>
                  <div className="cd-notify-recipients-list">
                    {wizardForm.selectedGroups.map((g) => (
                      <div key={g} className="cd-notify-recipient-row" style={{ cursor: 'default' }}>
                        <div className="cd-notify-recipient-info">
                          <span className="cd-avatar cd-avatar--sm">
                            {g.split(/\s+/).slice(0, 2).map((w) => w[0]?.toUpperCase() ?? '').join('')}
                          </span>
                          <div>
                            <div className="cd-notify-recipient-name">{g}</div>
                            <div className="cd-notify-recipient-role">Notify group</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right: compose */}
                <div className="cd-notify-right">
                  <div className="cd-notify-template-row">
                    <span className="cd-notify-template-label">Template</span>
                    <select
                      className="cd-notify-template-select"
                      value={wizardNotifyTemplate}
                      onChange={(e) => setWizardNotifyTemplate(e.target.value as NotifyTemplate)}
                    >
                      {(Object.entries(WIZARD_NOTIFY_TEMPLATES) as [NotifyTemplate, { label: string }][]).map(([key, tpl]) => (
                        <option key={key} value={key}>{tpl.label}</option>
                      ))}
                    </select>
                  </div>

                  <div className="cd-notify-field">
                    <label className="cd-notify-field-label">Subject</label>
                    <input
                      className="cd-notify-subject-input"
                      value={wizardNotifySubject}
                      onChange={(e) => setWizardNotifySubject(e.target.value)}
                    />
                  </div>

                  <div className="cd-notify-field">
                    <label className="cd-notify-field-label">Message</label>
                    <textarea
                      ref={wizardNotifyBodyRef}
                      className="cd-notify-body-textarea"
                      value={wizardNotifyBody}
                      onChange={(e) => setWizardNotifyBody(e.target.value)}
                      rows={9}
                    />
                  </div>

                  <div className="cd-notify-vars-row">
                    <span className="cd-notify-vars-label">Insert variable:</span>
                    {WIZARD_NOTIFY_VARIABLES.map((v) => (
                      <button key={v} type="button" className="cd-notify-var-chip" onClick={() => insertWizardVariable(v)}>
                        {v}
                      </button>
                    ))}
                  </div>

                  <div className="cd-notify-send-row">
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => setWizardNotifySent(true)}
                    >
                      Send email to {wizardForm.selectedGroups.length} group{wizardForm.selectedGroups.length !== 1 ? 's' : ''}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Post-creation notify toast */}
      {notifyToast && (
        <div className="campaigns-notify-toast">
          <span className="campaigns-notify-toast-icon">✓</span>
          <span>Notifications sent to {notifyToast.count} group{notifyToast.count !== 1 ? 's' : ''}</span>
        </div>
      )}
    </div>
  );
}
