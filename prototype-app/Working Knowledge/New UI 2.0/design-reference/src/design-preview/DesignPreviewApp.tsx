import React from 'react';
import {
  Activity, BookOpen, Bot, Boxes, Building2, ChevronDown, Clock, Flag, Gauge, LogOut, Moon, PanelLeftClose,
  PanelLeftOpen, Plug, Scale, Search, Settings, Shield, ShieldCheck, SlidersHorizontal, Sun, UserRound, Users, Layers as LayersIcon,
} from 'lucide-react';
import { TENANTS } from './data';
import { flattenNav, PATTERN_REFERENCE, PLATFORM_NAV, TENANT_NAV, type NavGroup, type NavLeaf } from './nav';
import { CommandPalette, type Command } from './components/CommandPalette';
import { ToastProvider } from './components/feedback';
import { Modal } from './components/overlays';
import { OverviewPage } from './pages/OverviewPage';
import { FindingsPage } from './pages/FindingsPage';
import { AiFindingsReferencePage } from './pages/AiFindingsReferencePage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { ConnectPage } from './pages/ConnectPage';
import { ConfigurationsPage } from './pages/ConfigurationsPage';
import { PlatformTenantsPage } from './pages/PlatformTenantsPage';
import { LoginPage } from './pages/LoginPage';
import { ComponentsPage } from './pages/ComponentsPage';
import { ReferenceHubPage } from './pages/ReferenceHubPage';
import { WorkbenchPage } from './pages/WorkbenchPage';
import { AiAssetPage } from './pages/AiAssetPage';
import { InventoryReferencePage } from './pages/InventoryReferencePage';
import { PolicyDistributionPage } from './pages/PolicyDistributionPage';
import { ScenarioPage, ROLES } from './pages/ScenarioPage';
import { ScenarioFrame, SCENARIOS } from './components/ScenarioFrame';
import { DEFAULT_PREVIEW, PreviewContext, type PreviewState } from './previewContext';

const ICONS: Record<string, React.ReactNode> = {
  gauge: <Gauge size={16} />, shield: <Shield size={16} />, book: <BookOpen size={16} />, flag: <Flag size={16} />,
  boxes: <Boxes size={16} />, scale: <Scale size={16} />, bot: <Bot size={16} />, plug: <Plug size={16} />,
  settings: <Settings size={16} />, users: <Users size={16} />, building: <Building2 size={16} />,
  clock: <Clock size={16} />, shieldCheck: <ShieldCheck size={16} />, activity: <Activity size={16} />,
};

const PERSONAS = [
  { id: 'analyst', label: 'Security Analyst', role: 'SECURITY_ANALYST' },
  { id: 'auditor', label: 'Read-only Auditor', role: 'READ_ONLY_AUDITOR' },
  { id: 'inventory', label: 'Inventory Admin', role: 'INVENTORY_ADMIN' },
];

/** Same fallback as App.tsx getInitialTheme(): dark unless the user chose light. */
function readTheme(): 'light' | 'dark' {
  try {
    return localStorage.getItem('scoutai-theme') === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

function readRoute(): string {
  const raw = window.location.hash.replace(/^#/, '') || '/reference';
  return raw.split('#')[0];
}

/** Mirrors App.tsx pageTitle mapping so headings (and tests that read them) keep their text. */
function pageTitleFor(route: string, scope: PreviewState['scope']): string {
  if (route.startsWith('/exposure')) return 'Exposure Dashboard';
  if (route.startsWith('/findings')) return 'Findings';
  if (route.startsWith('/connect')) return 'Connectors';
  if (route.startsWith('/configurations')) return 'Configurations';
  if (route.startsWith('/platform/ai-policies')) return 'Policy Distribution';
  if (route.startsWith('/platform')) return 'Tenant Management';
  if (route.startsWith('/inventory/ai')) return 'AI Asset Detail';
  if (route.startsWith('/inventory')) return 'Inventory';
  if (route.startsWith('/vuln-repo/org-cves')) return 'CVE Assessment Workbench';
  if (route.startsWith('/reference/scenarios')) return 'States & Permissions';
  if (route.startsWith('/reference')) return 'Design Review';
  if (route.startsWith('/components')) return 'Component Library';
  return scope === 'platform' ? 'Tenant Management' : 'Exposure Dashboard';
}

export function DesignPreviewApp() {
  const [route, setRoute] = React.useState(readRoute);
  const [theme, setTheme] = React.useState<'light' | 'dark'>(readTheme);
  const [collapsed, setCollapsed] = React.useState(false);
  const [navOpen, setNavOpen] = React.useState(false);
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [personaDialog, setPersonaDialog] = React.useState(false);
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const [controlsOpen, setControlsOpen] = React.useState(false);
  const [expanded, setExpanded] = React.useState<Set<string>>(() => new Set(['Findings']));
  const [preview, setPreview] = React.useState<PreviewState>(() => ({ ...DEFAULT_PREVIEW, scope: readRoute().startsWith('/platform') ? 'platform' : 'tenant' }));
  const contentRef = React.useRef<HTMLElement>(null);
  React.useLayoutEffect(() => { if (contentRef.current) contentRef.current.scrollTop = 0; }, [route]);

  React.useEffect(() => {
    const onHash = () => { setRoute(readRoute()); setNavOpen(false); setSettingsOpen(false); };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('scoutai-theme', theme); } catch { /* preview only */ }
  }, [theme]);

  React.useEffect(() => {
    if (!preview.enhancements) return;
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setPaletteOpen((o) => !o); }
      if ((event.metaKey || event.ctrlKey) && event.key === '\\') { event.preventDefault(); setCollapsed((v) => !v); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [preview.enhancements]);

  const go = React.useCallback((next: string) => {
    setPreview(current => next.startsWith('/platform') ? { ...current, scope: 'platform' } : /^\/(inventory|findings|exposure|configurations|connect|vuln-repo)/.test(next) ? { ...current, scope: 'tenant' } : current);
    window.location.hash = next;
  }, []);
  const updatePreview = (patch: Partial<PreviewState>) => { setPreview(current => ({ ...current, ...patch })); if (patch.enhancements === false) { setCollapsed(false); setPaletteOpen(false); } };

  if (route.startsWith('/login')) {
    return <LoginPage onSignIn={() => go('/exposure')} />;
  }

  const nav: NavGroup[] = preview.scope === 'platform' ? PLATFORM_NAV : TENANT_NAV.map(group => ({ ...group, items: group.items.filter(item => (preview.aiEntitled || !['AI Policies', 'AI Inventory'].includes(item.label)) && (preview.role === 'TENANT_ADMIN' || !['Configurations', 'Administration'].includes(item.label))).map(item => item.label === 'Findings' && !preview.aiEntitled ? { ...item, children: item.children?.filter(child => child.label !== 'AI Findings') } : item) }));
  const leaves = flattenNav(nav);
  const tenant = TENANTS[0];
  const tenantLabel = preview.scope === 'tenant' ? tenant.name : 'Platform';
  const displayRole = preview.scope === 'tenant' ? preview.role.replace(/_/g, ' ') : 'PLATFORM OWNER';
  const placeholder = leaves.find((leaf) => leaf.mock === undefined && `/x${leaf.appPath}` === route);
  const isActive = (leaf: NavLeaf) => leaf.label === 'Vulnerability Findings' && route.startsWith('/findings/ai') ? false : (leaf.mock ? route === leaf.mock || route.startsWith(`${leaf.mock}/`) || route.startsWith(`${leaf.mock}?`) : `/x${leaf.appPath}` === route);
  const leafRoute = (leaf: NavLeaf) => leaf.mock ?? `/x${leaf.appPath}`;

  const commands: Command[] = [
    ...leaves.map((leaf) => ({ id: `nav-${leaf.appPath}-${leaf.label}`, group: 'Go to', label: leaf.label, hint: leaf.appPath, run: () => go(leafRoute(leaf)) })),
    { id: 'components', group: 'Reference', label: 'Component library', run: () => go('/components') },
    { id: 'login', group: 'Reference', label: 'Login screen', run: () => go('/login') },
    { id: 'theme', group: 'Actions', label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', run: () => setTheme(theme === 'dark' ? 'light' : 'dark') },
  ];

  const toggleGroup = (label: string) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(label)) next.delete(label); else next.add(label);
    return next;
  });

  const renderGroup = (group: NavGroup, index: number) => (
    <div className="dp-nav-group" key={group.title ?? `g${index}`}>
      {group.title ? <div className="dp-nav-title">{group.title}</div> : null}
      {group.items.map((item) => {
        const childActive = item.children?.some(isActive) ?? false;
        const open = expanded.has(item.label) && !collapsed;
        return (
          <div key={item.label}>
            {/* Same affordance as App.tsx renderExpandableNavButton: label navigates, caret toggles. */}
            <button
              type="button"
              className={`dp-nav-item${isActive(item) || childActive ? ' active' : ''}`}
              title={collapsed ? item.label : undefined}
              onClick={() => go(leafRoute(item))}
            >
              <span className="dp-nav-icon">{ICONS[item.icon]}</span>
              <span className="dp-nav-label">{item.label}</span>
              {item.children ? (
                <span
                  className={`dp-nav-caret${open ? ' open' : ''}`}
                  role="button"
                  tabIndex={0}
                  aria-label={open ? `Collapse ${item.label} sections` : `Expand ${item.label} sections`}
                  onClick={(event) => { event.stopPropagation(); toggleGroup(item.label); }}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); event.stopPropagation(); toggleGroup(item.label); }
                  }}
                >
                  <ChevronDown size={14} />
                </span>
              ) : null}
            </button>
            {item.children && open ? (
              <div className="dp-nav-sub">
                {item.children.map((child) => (
                  <button key={child.label} type="button" className={`dp-nav-subitem${isActive(child) ? ' active' : ''}`} onClick={() => go(leafRoute(child))}>
                    {child.label}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );

  let page: React.ReactNode;
  if (route === '/reference/scenarios') page = <ScenarioPage state={preview} onChange={updatePreview} onNavigate={go} />;
  else if (route.startsWith('/reference')) page = <ReferenceHubPage onNavigate={go} />;
  else if (route.startsWith('/vuln-repo/org-cves')) page = <WorkbenchPage onNavigate={go} />;
  else if (route.startsWith('/inventory/ai')) page = <AiAssetPage onNavigate={go} />;
  else if (route.startsWith('/inventory')) page = <InventoryReferencePage onNavigate={go} />;
  else if (route.startsWith('/platform/ai-policies')) page = <PolicyDistributionPage route={route} onNavigate={go} />;
  else if (route.startsWith('/exposure')) page = <OverviewPage onNavigate={go} />;
  else if (route.startsWith('/findings/ai')) page = <AiFindingsReferencePage key={route.split('?')[0]} route={route} onNavigate={go} />;
  else if (/^\/findings\/.+/.test(route)) page = <FindingDetailPage id={route.split('/')[2]} onNavigate={go} />;
  else if (route.startsWith('/findings')) page = <FindingsPage onNavigate={go} />;
  else if (route.startsWith('/connect')) page = <ConnectPage route={route} onNavigate={go} />;
  else if (route.startsWith('/configurations')) page = <ConfigurationsPage route={route} onNavigate={go} />;
  else if (route.startsWith('/platform')) page = <PlatformTenantsPage />;
  else if (route.startsWith('/components')) page = <ComponentsPage />;
  else page = (
    <div className="dp-empty">
      <div className="dp-empty-icon"><SlidersHorizontal size={22} /></div>
      <h2>{placeholder?.label ?? 'Not in the reference'}</h2>
      <p>
        App route <code>{placeholder?.appPath ?? route}</code> is not mocked individually. Build it from the
        <strong> {PATTERN_REFERENCE[placeholder?.pattern ?? 'list'].label}</strong> pattern.
      </p>
      <div className="dp-empty-actions">
        <button type="button" className="dp-btn dp-btn--primary" onClick={() => go(PATTERN_REFERENCE[placeholder?.pattern ?? 'list'].mock.split('#')[0])}>Open pattern</button>
        <button type="button" className="dp-btn" onClick={() => go('/components')}>Component library</button>
      </div>
    </div>
  );

  return (
    <PreviewContext.Provider value={preview}>
      <ToastProvider>
        <div className={`dp-shell${collapsed ? ' collapsed' : ''}${navOpen ? ' nav-open' : ''}`}>
          <aside className="dp-sidebar" aria-label="Primary">
            <div className="dp-brand">
              <span className="dp-brand-mark">S</span>
              <span className="dp-brand-name">Scout</span>
            </div>
            {preview.enhancements ? <button type="button" className="dp-sidebar-search" onClick={() => setPaletteOpen(true)} title="Optional enhancement — see README">
              <Search size={14} /><span>Jump to…</span><kbd>⌘K</kbd>
            </button> : null}
            <nav className="dp-nav">{nav.filter((g) => g.placement !== 'bottom').map(renderGroup)}</nav>
            <div className="dp-nav dp-nav--bottom">{nav.filter((g) => g.placement === 'bottom').map(renderGroup)}</div>
          </aside>
          <div className="dp-nav-scrim" onClick={() => setNavOpen(false)} />

          <div className="dp-main">
            <header className="dp-topbar">
              {preview.enhancements ? <button type="button" className="dp-icon-btn dp-collapse-btn" onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar" title="Collapse sidebar (⌘\)">
                {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
              </button> : null}
              <button type="button" className="dp-btn dp-btn--sm dp-nav-toggle" onClick={() => setNavOpen(!navOpen)}>{navOpen ? 'Close Menu' : 'Menu'}</button>
              <nav className="dp-breadcrumb" aria-label="Breadcrumb">
                <span>{tenantLabel}</span>
                <span className="dp-breadcrumb-sep">/</span>
                <strong>{placeholder?.label ?? pageTitleFor(route, preview.scope)}</strong>
              </nav>
              <div className="dp-topbar-actions"><button type="button" className="dp-btn dp-btn--ghost dp-btn--sm dp-hub-link" onClick={() => go('/reference')}><LayersIcon /><span>Review hub</span></button>
                {preview.persona ? (
                  <>
                    <div className="dp-persona-pill" title="Persona preview">
                      <span>Impersonating: {preview.persona}</span>
                      <small>UI preview only</small>
                    </div>
                    <div className="dp-persona-warning" role="status">UI preview only - backend authorization still uses the current real session.</div>
                  </>
                ) : null}
                <button
                  type="button"
                  className="dp-icon-btn"
                  onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                  aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                  title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
                >
                  {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                </button>
                <div className="dp-popover-wrap">
                  <button
                    type="button"
                    className="dp-account-pill"
                    aria-label="Open account menu"
                    aria-expanded={settingsOpen}
                    title={`jordan.avery@acme.example · ${displayRole}`}
                    onClick={() => setSettingsOpen(!settingsOpen)}
                  >
                    <span className="dp-account-avatar"><UserRound size={14} /></span>
                    <span className="dp-account-copy"><span>{tenantLabel}</span><small>{displayRole.toLowerCase()}</small></span>
                    <ChevronDown size={14} className="dp-muted" />
                  </button>
                  {settingsOpen ? (
                    <div className="dp-popover dp-popover--right dp-settings-menu" role="menu" style={{ width: 260 }}>
                      <div className="dp-settings-head">
                        <strong>Settings</strong>
                        <span>jordan.avery@acme.example</span>
                      </div>
                      <button type="button" role="menuitem" className="dp-menu-item dp-menu-item--stack" onClick={() => { setSettingsOpen(false); setPersonaDialog(true); }}>
                        <span>Impersonate User</span><small>Open non-production test personas</small>
                      </button>
                      {preview.scope === 'platform' ? (
                        <button type="button" role="menuitem" className="dp-menu-item dp-menu-item--stack" onClick={() => setSettingsOpen(false)}>
                          <span>Authorized Workspaces</span><small>Open only tenant-approved access</small>
                        </button>
                      ) : null}
                      <div className="dp-menu-sep" />
                      <button type="button" role="menuitem" className="dp-menu-item" onClick={() => go('/login')}><LogOut size={14} /><span>Log out</span></button>
                    </div>
                  ) : null}
                </div>
              </div>
            </header>
            <main className="dp-content" ref={contentRef}>{route.startsWith('/reference') || route.startsWith('/components') ? page : <ScenarioFrame state={preview} onReset={() => updatePreview({ scenario: 'ready', loading: false })}>{page}</ScenarioFrame>}</main>
          </div>

          <div className={`dp-ref-controls${controlsOpen ? ' open' : ''}`}>
            <button type="button" className="dp-ref-toggle" onClick={() => setControlsOpen(!controlsOpen)} aria-expanded={controlsOpen}>
              <SlidersHorizontal size={14} /> Reference controls
            </button>
            {controlsOpen ? (
              <div className="dp-ref-panel">
                <div className="dp-ref-note">Mock-only switches. Not product UI.</div>
                <label>Scope
                  <select value={preview.scope} onChange={(e) => { setPreview({ ...preview, scope: e.target.value as PreviewState['scope'] }); go(e.target.value === 'tenant' ? '/exposure' : '/platform/tenants'); }}>
                    <option value="tenant">Tenant workspace</option>
                    <option value="platform">Platform scope</option>
                  </select>
                </label>
                <label>Tenant role<select aria-label="Reference tenant role" value={preview.role} disabled={preview.scope === 'platform'} onChange={e => updatePreview({ role: e.target.value as PreviewState['role'] })}>{ROLES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
                <label>Scenario<select aria-label="Reference scenario" value={preview.scenario} onChange={e => updatePreview({ scenario: e.target.value as PreviewState['scenario'] })}>{SCENARIOS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
                <label className="dp-ref-check"><input type="checkbox" checked={preview.aiEntitled} onChange={e => updatePreview({ aiEntitled: e.target.checked })} /> AI Security entitlement</label>
                <label className="dp-ref-check"><input type="checkbox" checked={preview.enhancements} onChange={e => updatePreview({ enhancements: e.target.checked })} /> Optional UI enhancements</label>
                <label className="dp-ref-check"><input type="checkbox" checked={preview.loading} onChange={(e) => setPreview({ ...preview, loading: e.target.checked })} /> Show loading states</label>
                <div className="dp-ref-links">
                  <button type="button" className="dp-link" onClick={() => go('/components')}>Component library</button><button type="button" className="dp-link" onClick={() => go('/reference/scenarios')}>States & permissions</button>
                  <button type="button" className="dp-link" onClick={() => go('/login')}>Login</button>
                </div>
              </div>
            ) : null}
          </div>

          <Modal
            open={personaDialog}
            onClose={() => setPersonaDialog(false)}
            title="Impersonate User"
            description="Non-production test personas. Backend impersonation swaps the session; preview only changes the UI."
            footer={<button type="button" className="dp-btn" onClick={() => { setPreview({ ...preview, persona: null }); setPersonaDialog(false); }}>Reset persona</button>}
          >
            <div className="dp-persona-list">
              {PERSONAS.map((persona) => (
                <div key={persona.id} className="dp-persona-row">
                  <div><strong>{persona.label}</strong><span className="dp-mono dp-muted">{persona.role}</span></div>
                  <button type="button" className="dp-btn dp-btn--sm">Impersonate</button>
                  <button type="button" className="dp-btn dp-btn--sm" onClick={() => { setPreview({ ...preview, persona: persona.label, role: persona.role as PreviewState['role'] }); setPersonaDialog(false); }}>Preview UI</button>
                </div>
              ))}
            </div>
          </Modal>

          <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
        </div>
      </ToastProvider>
    </PreviewContext.Provider>
  );
}
