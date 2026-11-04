import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { clearStoredAuthToken, getStoredAuthToken } from '../../api/client';
import { BrandMark } from '../../components/BrandMark';

export const SITE_NAME = 'Scoutgrid';
export const LEGAL_ENTITY = 'Axoncyber Private Limited';

export function SiteLogo() {
  return (
    <span className="sgw-logo">
      <BrandMark className="sgw-logo-mark" />
      <span className="sgw-logo-text">
        <span className="sgw-logo-word">{SITE_NAME}</span>
        <span className="sgw-logo-tag">– AI Security</span>
      </span>
    </span>
  );
}

const NAV_SECTIONS = [
  { label: 'Platform', to: '/demo#platform' },
  { label: 'Products', to: '/demo#products' },
  { label: 'Solutions', to: '/demo#solutions' }
];

const RESOURCE_LINKS = [
  { label: 'Blog', to: '/demo/blog' },
  { label: 'Announcements', to: '/demo/announcements' }
];

const COMPANY_LINKS = [
  { label: 'Partners', to: '/demo/partners' },
  { label: 'Contact', to: '/demo/contact' }
];

// Disclosure menu: a button that shows a short list of links. Closes on Escape,
// an outside click, focus leaving the menu, or navigation.
function DisclosureMenu({ label, links }: { label: string; links: Array<{ label: string; to: string }> }) {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const buttonRef = React.useRef<HTMLButtonElement>(null);
  const location = useLocation();
  const menuId = React.useId();
  const active = links.some((link) => location.pathname.startsWith(link.to));

  React.useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  React.useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div
      ref={rootRef}
      className="sgw-menu"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false);
      }}
    >
      <button
        ref={buttonRef}
        type="button"
        className={active ? 'sgw-menu-button is-active' : 'sgw-menu-button'}
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((current) => !current)}
      >
        {label}
        <svg className="sgw-menu-caret" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
          <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      <ul id={menuId} className="sgw-menu-panel" hidden={!open}>
        {links.map((link) => (
          <li key={link.label}><Link to={link.to}>{link.label}</Link></li>
        ))}
      </ul>
    </div>
  );
}

function SiteHeader({ onLogout }: { onLogout?: () => void }) {
  return (
    <header className="sgw-nav">
      <div className="sgw-nav-inner">
        <Link to="/demo" className="sgw-nav-brand" aria-label={`${SITE_NAME} home`}>
          <SiteLogo />
        </Link>
        <nav className="sgw-nav-links" aria-label={`${SITE_NAME} site`}>
          {NAV_SECTIONS.map((section) => (
            <Link key={section.label} to={section.to}>{section.label}</Link>
          ))}
          <DisclosureMenu label="Resources" links={RESOURCE_LINKS} />
          <DisclosureMenu label="Company" links={COMPANY_LINKS} />
        </nav>
        <div className="sgw-nav-actions">
          <Link className="sgw-nav-login" to="/login">Log in</Link>
          <Link className="sgw-btn sgw-btn-red sgw-nav-cta" to="/demo/contact">
            Request a demo
          </Link>
          {onLogout && (
            <button className="sgw-nav-logout" type="button" onClick={onLogout}>
              Log out
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

const FOOTER_COLUMNS: Array<{ title: string; links: Array<{ label: string; to: string }> }> = [
  {
    title: 'Products',
    links: [
      { label: 'AI Grid', to: '/demo#ai-grid' },
      { label: 'Infra Grid', to: '/demo#products' },
      { label: 'BOM Grid', to: '/demo#products' },
      { label: 'Cloud Grid', to: '/demo#products' }
    ]
  },
  {
    title: 'Solutions',
    links: [
      { label: 'Vulnerability Intelligence', to: '/demo#solutions' },
      { label: 'Fix Intelligence', to: '/demo#solutions' },
      { label: 'EOL Information', to: '/demo#solutions' },
      { label: 'Campaigns', to: '/demo#act' },
      { label: 'Exception Management', to: '/demo#act' },
      { label: 'AI-powered Solutions', to: '/demo#act' }
    ]
  },
  {
    title: 'Explore',
    links: [
      { label: 'Platform', to: '/demo#platform' },
      { label: 'Blog', to: '/demo/blog' },
      { label: 'Announcements', to: '/demo/announcements' },
      { label: 'Request a demo', to: '/demo/contact' },
      { label: 'Log in', to: '/login' }
    ]
  },
  {
    title: 'Company',
    links: [
      { label: 'Partners', to: '/demo/partners' },
      { label: 'Contact', to: '/demo/contact' }
    ]
  }
];

function SiteFooter() {
  return (
    <footer className="sgw-footer">
      <div className="sgw-wrap">
        <div className="sgw-footer-grid">
          <div className="sgw-footer-brand">
            <SiteLogo />
            <p>A clearer perspective on exposure. For the AI era.</p>
          </div>
          {FOOTER_COLUMNS.map((column) => (
            <div key={column.title} className="sgw-footer-col">
              <h2 className="sgw-label">{column.title}</h2>
              <ul>
                {column.links.map((link) => (
                  <li key={link.label}><Link to={link.to}>{link.label}</Link></li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="sgw-footer-bottom">
          <span>© 2026 {LEGAL_ENTITY}. All rights reserved. {SITE_NAME} is a product of {LEGAL_ENTITY}.</span>
          <span className="sgw-footer-legal">
            <Link to="/demo/privacy">Privacy</Link>
            <Link to="/demo/terms">Terms</Link>
            <Link to="/demo/cookies">Cookies</Link>
          </span>
        </div>
      </div>
    </footer>
  );
}

export function PublicDemoShell({
  children,
  compact = false,
  authEntry = false
}: {
  children: React.ReactNode;
  compact?: boolean;
  authEntry?: boolean;
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const [hasStoredToken, setHasStoredToken] = React.useState(() => getStoredAuthToken().trim().length > 0);

  React.useEffect(() => {
    setHasStoredToken(getStoredAuthToken().trim().length > 0);
  }, [location.pathname, location.search]);

  const logout = React.useCallback(() => {
    clearStoredAuthToken();
    setHasStoredToken(false);
    navigate('/login', { replace: true });
  }, [navigate]);

  const mainClass = [
    'public-demo-shell',
    compact ? 'compact' : '',
    authEntry ? 'ui2-experience-family' : ''
  ].filter(Boolean).join(' ');

  return (
    <div className={authEntry ? 'sgw-site sgw-site--auth' : 'sgw-site'}>
      <SiteHeader onLogout={hasStoredToken ? logout : undefined} />
      <main className={mainClass}>{children}</main>
      {!authEntry && <SiteFooter />}
    </div>
  );
}
