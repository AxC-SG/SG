import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { AiDiamondGraphic, ConnectionsGraphic, HeroSurfaceGraphic, SiteIcon } from './graphics';
import { PublicDemoShell } from './PublicSiteShell';

const REQUEST_PATH = '/demo/request';

const GRIDS: Array<{ id: string; icon: 'sparkle' | 'server' | 'boxes' | 'cloud'; title: string; body: string; tag?: string }> = [
  { id: 'ai', icon: 'sparkle', title: 'AI Grid', body: 'Bring your expanding AI exposure into focus.', tag: 'AI security' },
  { id: 'infra', icon: 'server', title: 'Infra Grid', body: 'See the risk across your infrastructure.' },
  { id: 'bom', icon: 'boxes', title: 'BOM Grid', body: 'Understand what your software depends on.' },
  { id: 'cloud', icon: 'cloud', title: 'Cloud Grid', body: 'Keep cloud exposure in perspective.' }
];

const CONTEXT_SOLUTIONS: Array<{ icon: 'scan' | 'wrench' | 'hourglass'; title: string; body: string }> = [
  { icon: 'scan', title: 'Vulnerability Intelligence', body: 'Separate relevant risk from the surrounding noise.' },
  { icon: 'wrench', title: 'Fix Intelligence', body: 'Bring clarity to the next best action.' },
  { icon: 'hourglass', title: 'EOL Information', body: 'Stay ahead of the risk in aging technology.' }
];

const ACTION_SOLUTIONS: Array<{ icon: 'flag' | 'branch' | 'sparkle'; title: string; body: string }> = [
  { icon: 'flag', title: 'Campaigns', body: 'Align your teams around the risk worth reducing.' },
  { icon: 'branch', title: 'Exception Management', body: 'Make accepted risk a deliberate decision.' },
  { icon: 'sparkle', title: 'AI-powered Solutions', body: 'Bring intelligent support to complex security decisions.' }
];

const AUDIENCES = [
  { label: 'Security leaders', line: 'A clearer view of what matters.' },
  { label: 'Security teams', line: 'A shared focus for reducing exposure.' },
  { label: 'AI & technology teams', line: 'Room to innovate with risk in view.' }
];

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="sgw-label sgw-eyebrow">{children}</p>;
}

function ArrowLink({ to, children, className }: { to: string; children: React.ReactNode; className?: string }) {
  return (
    <Link className={className ? `sgw-arrow-link ${className}` : 'sgw-arrow-link'} to={to}>
      <span>{children}</span>
      <SiteIcon name="arrow" />
    </Link>
  );
}

function SolutionRow({ items }: { items: Array<{ icon: Parameters<typeof SiteIcon>[0]['name']; title: string; body: string }> }) {
  return (
    <ul className="sgw-solution-row">
      {items.map((item) => (
        <li key={item.title}>
          <SiteIcon name={item.icon} className="sgw-red-icon" />
          <h3>{item.title}</h3>
          <p>{item.body}</p>
        </li>
      ))}
    </ul>
  );
}

// Section links from the top bar and footer arrive as a hash; scroll once the section exists.
function useHashScroll() {
  const location = useLocation();
  React.useEffect(() => {
    const id = location.hash.replace(/^#/, '');
    if (!id) return;
    const target = document.getElementById(decodeURIComponent(id));
    if (target && typeof target.scrollIntoView === 'function') {
      target.scrollIntoView({ block: 'start' });
    }
  }, [location.hash, location.key]);
}

export function PublicLandingPage() {
  useHashScroll();

  return (
    <PublicDemoShell>
      <div className="sgw-landing">
        <section className="sgw-section sgw-dark sgw-hero" aria-labelledby="sgw-hero-title">
          <div className="sgw-wrap sgw-hero-grid">
            <div className="sgw-hero-copy">
              <Eyebrow>AI-first exposure management</Eyebrow>
              <h1 id="sgw-hero-title">
                Secure AI.<br />See the whole <span className="sgw-red-text">exposure.</span>
              </h1>
              <p className="sgw-lead">AI is changing your attack surface. Bring it into focus with the rest of your enterprise.</p>
              <div className="sgw-hero-actions">
                <Link className="sgw-btn sgw-btn-red" to={REQUEST_PATH}>
                  Request a demo <SiteIcon name="arrow" />
                </Link>
                <Link className="sgw-text-link" to="/demo#products">
                  Meet the four Grids <SiteIcon name="arrowDown" />
                </Link>
              </div>
            </div>
            <div className="sgw-hero-visual">
              <HeroSurfaceGraphic />
              <div className="sgw-hero-caption">
                <span className="sgw-label">Connected exposure. Clearer signal.</span>
                <span className="sgw-label sgw-red-text">SG / AI</span>
              </div>
            </div>
          </div>
          <div className="sgw-strip">
            <div className="sgw-wrap sgw-strip-inner">
              <span className="sgw-label">One platform. Four Grids.</span>
              <ol className="sgw-strip-grids">
                {GRIDS.map((grid, index) => (
                  <li key={grid.id}>
                    <span className={index === 0 ? 'sgw-label sgw-red-text' : 'sgw-label'}>0{index + 1}</span>
                    {grid.title}
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </section>

        <section id="platform" className="sgw-section sgw-light" aria-labelledby="sgw-challenge-title">
          <div className="sgw-wrap sgw-split">
            <div>
              <Eyebrow>The challenge has changed</Eyebrow>
              <h2 id="sgw-challenge-title" className="sgw-h2">AI doesn&rsquo;t exist in isolation. Neither should its security.</h2>
            </div>
            <p className="sgw-side-copy">
              Your AI, infrastructure, software supply chain and cloud are connected. Your understanding of exposure should be, too.
            </p>
          </div>
        </section>

        <section id="products" className="sgw-section sgw-light sgw-grids" aria-labelledby="sgw-grids-title">
          <div className="sgw-wrap">
            <Eyebrow>The Scoutgrid platform</Eyebrow>
            <div className="sgw-split sgw-split--end">
              <h2 id="sgw-grids-title" className="sgw-h2">Four Grids.<br />A wider view of risk.</h2>
              <ArrowLink to={REQUEST_PATH}>Find your starting point</ArrowLink>
            </div>
            <ul className="sgw-grid-cards">
              {GRIDS.map((grid, index) => (
                <li key={grid.id} className={index === 0 ? 'sgw-grid-card sgw-grid-card--featured' : 'sgw-grid-card'}>
                  <div className="sgw-grid-card-top">
                    <SiteIcon name={grid.icon} className="sgw-red-icon" />
                    {grid.tag && <span className="sgw-label">{grid.tag}</span>}
                  </div>
                  <h3>{grid.title}</h3>
                  <p>{grid.body}</p>
                  <Link className="sgw-card-link" to={REQUEST_PATH}>
                    <span>Explore <span className="sgw-sr-only">{grid.title}</span> in a demo</span>
                    <SiteIcon name="arrow" />
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="ai-grid" className="sgw-section sgw-dark" aria-labelledby="sgw-ai-title">
          <div className="sgw-wrap sgw-focus-grid">
            <div>
              <Eyebrow>AI Grid / in focus</Eyebrow>
              <h2 id="sgw-ai-title" className="sgw-h2">Move AI forward.<br />Keep exposure in sight.</h2>
              <p className="sgw-lead">
                Give your AI ambitions a security perspective. Understand the exposure around AI, not just the technology itself.
              </p>
              <ArrowLink to={REQUEST_PATH}>Request an AI Grid demo</ArrowLink>
            </div>
            <AiDiamondGraphic />
          </div>
          <div className="sgw-wrap">
            <div className="sgw-pillars">
              <span className="sgw-label">Confidence for the AI era</span>
              <ul>
                <li>Know your AI landscape</li>
                <li>Understand connected risk</li>
                <li>Move with intent</li>
              </ul>
            </div>
          </div>
        </section>

        <section id="solutions" className="sgw-section sgw-light" aria-labelledby="sgw-context-title">
          <div className="sgw-wrap">
            <Eyebrow>Solutions / understand the signal</Eyebrow>
            <div className="sgw-split sgw-split--end">
              <h2 id="sgw-context-title" className="sgw-h2">Better context.<br />Sharper decisions.</h2>
              <p className="sgw-side-copy">Turn exposure information into a clearer security perspective.</p>
            </div>
            <SolutionRow items={CONTEXT_SOLUTIONS} />
          </div>
        </section>

        <section id="act" className="sgw-section sgw-paper" aria-labelledby="sgw-act-title">
          <div className="sgw-wrap">
            <Eyebrow>Solutions / act with purpose</Eyebrow>
            <div className="sgw-split sgw-split--end">
              <h2 id="sgw-act-title" className="sgw-h2">Make the next move count.</h2>
              <p className="sgw-side-copy">Connect security priorities to purposeful action.</p>
            </div>
            <SolutionRow items={ACTION_SOLUTIONS} />
          </div>
        </section>

        <section className="sgw-section sgw-dark" aria-labelledby="sgw-connections-title">
          <div className="sgw-wrap sgw-focus-grid">
            <div>
              <Eyebrow>The connected advantage</Eyebrow>
              <h2 id="sgw-connections-title" className="sgw-h2">The value is in the connections.</h2>
              <p className="sgw-lead">See beyond isolated findings. Keep your exposure in context across all four Grids.</p>
            </div>
            <figure className="sgw-network">
              <ConnectionsGraphic />
              <figcaption className="sgw-label">Different surfaces. A shared perspective.</figcaption>
            </figure>
          </div>
        </section>

        <section className="sgw-section sgw-light" aria-labelledby="sgw-audience-title">
          <div className="sgw-wrap sgw-split sgw-split--top">
            <div>
              <Eyebrow>Built for shared confidence</Eyebrow>
              <h2 id="sgw-audience-title" className="sgw-h2">Different perspectives.<br />One direction.</h2>
              <p className="sgw-side-copy">Give every conversation about exposure a common starting point.</p>
            </div>
            <ul className="sgw-audiences">
              {AUDIENCES.map((audience) => (
                <li key={audience.label}>
                  <span className="sgw-label sgw-red-text">{audience.label}</span>
                  <p>{audience.line}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="sgw-section sgw-dark sgw-final" aria-labelledby="sgw-final-title">
          <div className="sgw-wrap sgw-split sgw-split--end">
            <div>
              <span className="sgw-final-rule" aria-hidden="true" />
              <Eyebrow>Your next perspective</Eyebrow>
              <h2 id="sgw-final-title" className="sgw-h2 sgw-h2--xl">See your exposure in a different light.</h2>
            </div>
            <div className="sgw-final-cta">
              <p className="sgw-lead">Explore Scoutgrid in a private demo, tailored to your priorities. The detail belongs in the conversation.</p>
              <Link className="sgw-btn sgw-btn-red" to={REQUEST_PATH}>
                Request a demo <SiteIcon name="arrow" />
              </Link>
              <span className="sgw-label">AI Grid · Infra Grid · BOM Grid · Cloud Grid</span>
            </div>
          </div>
        </section>
      </div>
    </PublicDemoShell>
  );
}
