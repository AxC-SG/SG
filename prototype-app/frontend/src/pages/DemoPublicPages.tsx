import React from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { pathForConnectView } from '../app/routes';
import { api, setStoredAuthToken } from '../api/client';
import { getAuthContextQueryKey } from '../features/auth/queries';
import { canManageInventorySources, canManageRiskPolicy } from '../features/auth/roles';
import type { ActorContext } from '../features/auth/types';
import { AnnouncementsIndexPage, NvidiaInceptionAnnouncementPage } from '../features/public-site/Announcements';
import { PublicLandingPage } from '../features/public-site/LandingPage';
import { CookiePolicyPage, PrivacyPolicyPage, TermsOfServicePage } from '../features/public-site/LegalPages';
import { PublicDemoShell } from '../features/public-site/PublicSiteShell';
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';
const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY?.trim()
  || (import.meta.env.DEV ? '1x00000000000000000000AA' : '0x4AAAAAAD7ahchhUEu5jKLM');
// Mirrors the server-side minimum on /auth/setup-password (AuthSetupPasswordRequest).
const MIN_SETUP_PASSWORD_LENGTH = 12;
const FREE_EMAIL_DOMAINS = new Set([
  '126.com', '163.com', 'aol.com', 'fastmail.com', 'gmail.com', 'gmx.com', 'gmx.de', 'googlemail.com',
  'hey.com', 'hotmail.co.uk', 'hotmail.com', 'hushmail.com', 'icloud.com', 'inbox.com', 'laposte.net',
  'libero.it', 'live.co.uk', 'live.com', 'mac.com', 'mail.com', 'me.com', 'msn.com', 'orange.fr',
  'outlook.com', 'proton.me', 'protonmail.com', 'qq.com', 'rambler.ru', 'rediffmail.com', 'tuta.com',
  'tutanota.com', 'web.de', 'yahoo.co.in', 'yahoo.co.uk', 'yahoo.com', 'yahoo.in', 'yandex.com',
  'yandex.ru', 'zoho.com'
]);

type TurnstileOptions = {
  sitekey: string;
  action: string;
  theme: 'light';
  size: 'flexible';
  callback: (token: string) => void;
  'expired-callback': () => void;
  'error-callback': () => void;
};

type TurnstileApi = {
  render: (container: HTMLElement, options: TurnstileOptions) => string;
  reset: (widgetId: string) => void;
  remove: (widgetId: string) => void;
};

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

function isCorporateEmail(email: string): boolean {
  const normalized = email.trim().toLowerCase();
  const separator = normalized.lastIndexOf('@');
  if (separator <= 0 || separator !== normalized.indexOf('@')) return false;
  const domain = normalized.slice(separator + 1);
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) return false;
  if (FREE_EMAIL_DOMAINS.has(domain)) return false;
  return !/^(?:yahoo|hotmail|live)\./.test(domain);
}

// Why the verification token is absent, so the form can say what to do next.
type CaptchaClearReason = 'expired' | 'error' | 'reset';

function TurnstileWidget({
  onTokenChange,
  resetKey
}: {
  onTokenChange: (token: string | null, reason?: CaptchaClearReason) => void;
  resetKey: number;
}) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const widgetIdRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!TURNSTILE_SITE_KEY || !containerRef.current) return undefined;

    const renderWidget = () => {
      if (!window.turnstile || !containerRef.current || widgetIdRef.current) return;
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: TURNSTILE_SITE_KEY,
        action: 'demo_request',
        theme: 'light',
        size: 'flexible',
        callback: (token) => onTokenChange(token),
        'expired-callback': () => onTokenChange(null, 'expired'),
        'error-callback': () => onTokenChange(null, 'error')
      });
    };

    let script = document.querySelector<HTMLScriptElement>('script[data-scout-turnstile]');
    if (!script) {
      script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.defer = true;
      script.dataset.scoutTurnstile = 'true';
      document.head.appendChild(script);
    }
    script.addEventListener('load', renderWidget);
    renderWidget();

    return () => {
      script?.removeEventListener('load', renderWidget);
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current);
      }
      widgetIdRef.current = null;
    };
  }, [onTokenChange]);

  React.useEffect(() => {
    if (resetKey > 0 && widgetIdRef.current && window.turnstile) {
      window.turnstile.reset(widgetIdRef.current);
      onTokenChange(null, 'reset');
    }
  }, [onTokenChange, resetKey]);

  if (!TURNSTILE_SITE_KEY) {
    return <div className="notice error full-width">CAPTCHA is not configured. Please contact support.</div>;
  }
  return <div className="turnstile-field full-width" ref={containerRef} aria-label="CAPTCHA verification" />;
}

function PasswordInput({
  label,
  value,
  onChange,
  autoComplete,
  describedBy
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: 'current-password' | 'new-password';
  describedBy?: string;
}) {
  const [visible, setVisible] = React.useState(false);
  return (
    <label>
      {label}
      <span className="password-input-wrap">
        <input
          aria-label={label}
          aria-describedby={describedBy}
          autoComplete={autoComplete}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
        <button
          className="password-visibility-toggle"
          type="button"
          aria-label={visible ? 'Hide password' : 'Show password'}
          aria-pressed={visible}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18M10.6 10.7a2 2 0 002.7 2.7M9.9 4.2A10.7 10.7 0 0112 4c5.5 0 9 5.5 9 8a11.7 11.7 0 01-2.1 3.5M6.6 6.6C4.3 8.1 3 10.5 3 12c0 2.5 3.5 8 9 8a10 10 0 004.1-.9" /></svg>
          ) : (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12c0-2.5 3.5-8 9-8s9 5.5 9 8-3.5 8-9 8-9-5.5-9-8z" /><circle cx="12" cy="12" r="3" /></svg>
          )}
        </button>
      </span>
    </label>
  );
}

/** Backward-compatible name used by the existing /demo route. */
export function DemoLandingPage() {
  return <PublicLandingPage />;
}

export { AnnouncementsIndexPage, CookiePolicyPage, NvidiaInceptionAnnouncementPage, PrivacyPolicyPage, TermsOfServicePage };

const ZERO_DAY_BLOG_PATH = '/demo/blog/zero-day-response-hours-not-weeks';
const MYTHOS_READINESS_BLOG_PATH = '/demo/blog/mythos-readiness';
const SBOM_EXPLOITABILITY_BLOG_PATH = '/demo/blog/why-your-sbom-tool-doesnt-know-whats-exploitable';

export function BlogIndexPage() {
  return (
    <PublicDemoShell>
      <div className="blog-index-page">
        <header className="blog-hero">
          <div className="blog-page-width">
            <span className="blog-hero-eyebrow">Insights</span>
            <h1>Blog</h1>
            <p>Insights on exposure management, zero-day response, and security operations.</p>
          </div>
        </header>

        <section className="blog-list blog-page-width" aria-label="Scoutgrid blog posts">
          <article className="blog-card">
            <time dateTime="2026-07-19">July 19, 2026</time>
            <h2>
              <Link to={ZERO_DAY_BLOG_PATH}>
                Zero-day response: from disclosure to remediation in hours, not weeks
              </Link>
            </h2>
            <p>
              A zero-day response should not stall while teams rebuild context. See how Fix Intelligence and
              AI-assisted investigation turn days of manual digging into a clear remediation path in minutes.
            </p>
            <Link className="blog-read-more" to={ZERO_DAY_BLOG_PATH}>
              Read more <span aria-hidden="true">→</span>
            </Link>
          </article>
          <article className="blog-card">
            <time dateTime="2026-08-14">August 14, 2026</time>
            <h2>
              <Link to={SBOM_EXPLOITABILITY_BLOG_PATH}>Why your SBOM tool doesn&apos;t know what&apos;s actually exploitable</Link>
            </h2>
            <p>
              An SBOM tells you what is in your software. Scoutgrid keeps your exposure picture current so you know what is exploitable right now.
            </p>
            <Link className="blog-read-more" to={SBOM_EXPLOITABILITY_BLOG_PATH}>
              Read more <span aria-hidden="true">→</span>
            </Link>
          </article>
          <article className="blog-card">
            <time dateTime="2026-09-12">September 12, 2026</time>
            <h2>
              <Link to={MYTHOS_READINESS_BLOG_PATH}>Mythos readiness: why discovery was never the hard part</Link>
            </h2>
            <p>
              A concise readiness guide for understanding the Scoutgrid Mythos security posture and the steps that
              move an organization toward stronger AI governance.
            </p>
            <Link className="blog-read-more" to={MYTHOS_READINESS_BLOG_PATH}>
              Read more <span aria-hidden="true">→</span>
            </Link>
          </article>
        </section>
      </div>
    </PublicDemoShell>
  );
}

export function SbomExploitabilityBlogPage() {
  return (
    <PublicDemoShell>
      <article className="blog-article">
        <header className="blog-article-header">
          <Link className="blog-back-link" to="/demo/blog">← All blogs</Link>
          <span className="blog-article-kicker">SCOUTGRID BLOG · VULNERABILITY INTELLIGENCE</span>
          <h1>Why your SBOM tool doesn&apos;t know what&apos;s actually exploitable</h1>
          <p className="blog-article-deck">SBOM ingestion + continuous re-correlation — no re-scan needed when a new CVE drops.</p>
          <time dateTime="2026-08-14">August 14, 2026</time>
        </header>

        <div className="blog-article-body">
          <p>
            Most SBOM tools do one thing well: they tell you what&apos;s in your software. You get a component list, a compliance artifact, a box checked. But a component list is not a risk list — and that gap is exactly where real exposure hides.
          </p>
          <p>
            An SBOM is a snapshot. The day it&apos;s generated, it starts going out of date. New vulnerabilities are disclosed constantly, and some start being actively exploited within days. Your SBOM tool has no way of knowing that happened — it already did its job the moment it produced the document. Finding out whether today&apos;s risk still matches yesterday&apos;s snapshot means someone has to remember to re-scan, re-upload, or manually check. Most teams don&apos;t do that often enough for it to matter.
          </p>
          <p>
            A clean SBOM from last quarter isn&apos;t reassurance. It&apos;s a question nobody&apos;s asked recently.
          </p>

          <h2>What that gap actually costs your team</h2>
          <ul>
            <li><strong>Blind spots between scans.</strong> A newly disclosed, actively exploited vulnerability can sit unnoticed in your environment for days or weeks, simply because nobody triggered a fresh scan.</li>
            <li><strong>Wasted analyst time.</strong> Instead of fixing real issues, your team spends hours re-running scans and manually cross-checking whether anything changed.</li>
            <li><strong>False confidence.</strong> A clean report from last month feels reassuring — but it says nothing about your risk today.</li>
            <li><strong>Slow response to real threats.</strong> The vulnerabilities that matter most are the ones being exploited right now. A stale inventory means you find out late, after the exposure has already cost you.</li>
          </ul>

          <h2>How Scoutgrid closes the gap</h2>
          <p>Scoutgrid keeps your risk picture current automatically, so your team never has to chase it.</p>
          <ul>
            <li><strong>No re-scans, no re-uploads.</strong> Once your software inventory is in Scoutgrid, it stays protected — you don&apos;t need to re-run anything to stay current as new vulnerabilities emerge.</li>
            <li><strong>Always current, with zero extra effort.</strong> Your exposure picture reflects the latest known risks automatically,</li>
            <li><strong>Time back for your team.</strong> Analysts spend their time fixing what matters instead of re-verifying whether their data is still accurate.</li>
            <li><strong>Faster action on real threats.</strong> When a vulnerability starts being actively exploited in the wild, it&apos;s reflected in your priorities immediately — not at your next scheduled scan.</li>
            <li><strong>Confidence, not guesswork.</strong> You always know your current exposure is current — not a snapshot from whenever someone last remembered to check.</li>
          </ul>

          <h2>IN PRACTICE</h2>
          <p>
            A vulnerability becomes a headline because it&apos;s being actively exploited. With most tools, you&apos;d need to kick off a new scan to find out if it affects you. With Scoutgrid, your team already knows — and already knows exactly where to focus — before anyone has to ask.
          </p>

          <h2>The bigger picture</h2>
          <p>
            An SBOM answers a compliance question: what&apos;s in your software. Scoutgrid answers the question that actually matters day to day: what&apos;s exploitable right now, and what should your team fix first. That answer stays current on its own — so your team&apos;s time goes toward reducing risk, not maintaining an inventory.
          </p>

          <h2>KEY TAKEAWAYS</h2>
          <ul>
            <li>An SBOM is a snapshot — it goes stale the moment it&apos;s generated.</li>
            <li>Manual re-scanning doesn&apos;t scale, and the gap it leaves is exactly where exploited vulnerabilities hide.</li>
            <li>Scoutgrid keeps your exposure picture current automatically, so your team&apos;s time goes toward fixing risk, not chasing whether the data is still accurate.</li>
            <li>Your SBOM tool tells you what&apos;s in your software. Scoutgrid tells you what&apos;s exploitable — and keeps telling you, automatically, for as long as it matters.</li>
          </ul>
        </div>
      </article>
    </PublicDemoShell>
  );
}

export function MythosReadinessBlogPage() {
  return (
    <PublicDemoShell>
      <article className="blog-article">
        <header className="blog-article-header">
          <Link className="blog-back-link" to="/demo/blog">← All blogs</Link>
          <span className="blog-article-kicker">SCOUTGRID · MYTHOS READINESS BRIEF</span>
          <h1>Mythos Readiness: Why Discovery Was Never the Hard Part</h1>
          <p className="blog-article-deck">Claude Mythos Preview solved vulnerability discovery. Scoutgrid is built for what happens next.</p>
          <time dateTime="2026">Scoutgrid Product Team · 2026</time>
        </header>

        <div className="blog-article-body">
          <p>
            In April 2026, AWS, Apple, Google, Microsoft, and NVIDIA announced Project Glasswing — a defensive coalition
            built around Claude Mythos Preview, a frontier model purpose-built for deep code reasoning. Mythos doesn&rsquo;t just flag
            known CVEs faster than a scanner; it reads straight through opaque, complex codebases and surfaces high-severity
            vulnerabilities other tools never see at all.
          </p>
          <p>
            That capability won&rsquo;t stay confined to a handful of frontier labs. Within the next 12–18 months, comparable models
            will run against ordinary enterprise pipelines — and the organizations that come out ahead won&rsquo;t be the ones with the
            best scanner. Discovery is already solved. Readiness is about what happens the moment a model like Mythos hands
            you hundreds of new, real findings at once: can you coordinate a response, close the blind spots it finds, filter the noise
            it repeats, and fix things at the speed it discovers them?
          </p>

          <h2>Four Scoutgrid capabilities carry that response end to end:</h2>

          <section>
            <h2>Campaigns</h2>
            <p><em>Closes the gap: mass CVE disclosure with no coordinated response path.</em></p>
            <p>
              A 400-finding scan result shouldn&rsquo;t turn into a spreadsheet and a week of ownership disputes. Scoutgrid Campaigns
              auto-groups Mythos-scale findings by CVE, software, or asset, alerts notify groups and watchlists within the hour,
              and routes ownership through the same rules that already govern your findings — with velocity tracked live until the
              campaign closes.
            </p>
          </section>

          <section>
            <h2>BOM Grid</h2>
            <p><em>Closes the gap: fragmented bill-of-materials visibility across four BOM types.</em></p>
            <p>
              Frontier models trace what your code depends on — including AI/ML models, cryptographic primitives, and vendor
              components most tooling never looks at. BOM Grid unifies SBOM, AI BOM, CBOM, and Vendor BOM into one exposure grid,
              so nothing Mythos flags lands in a blind spot.
            </p>
          </section>

          <section>
            <h2>Suppression Rules</h2>
            <p><em>Closes the gap: alert fatigue from repeat, previously-accepted findings.</em></p>
            <p>
              A model that re-scans nightly will re-surface the same accepted-risk findings every run unless something filters
              them with a record of why. Scoutgrid keeps that filter governed instead of quiet: every suppressed finding carries a reason,
              an approver, and an expiry date, so yesterday&rsquo;s accepted risk doesn&rsquo;t quietly become tomorrow&rsquo;s blind spot.
            </p>
          </section>

          <section>
            <h2>Fix Intelligence</h2>
            <p><em>Closes the gap: remediation research lag behind AI-speed discovery.</em></p>
            <p>
              Mythos can surface a critical vulnerability far faster than a human can research the fix. Fix Intelligence generates
              the concrete remediation — an upgrade, a patch, a config change — per CVE or software identity, prioritizes the queue
              by exploitability and SLA proximity, and returns structured fallback guidance instead of a dead end when AI confidence is low.
            </p>
          </section>

          <section>
            <h2>Under the Hood: CVE Investigation</h2>
            <p>
              All four capabilities lean on the same engine. The moment a CVE shows up against your inventory, Scoutgrid automatically runs
              false-positive checks, end-of-life analysis, and exploit-status lookups — before a human opens the finding.
            </p>
            <p>
              That single step is what lets suppression decisions get made with confidence, feeds the recommendations behind Fix
              Intelligence, and turns a raw Mythos-flagged CVE into something a Campaign can assign as real work instead of noise.
              CVE Investigation is the foundation; the other four are what you build on top of it.
            </p>
          </section>

          <div className="blog-closing-callout">
            <strong>Mythos readiness isn&rsquo;t measured by how fast you can find what&rsquo;s wrong — that part is already solved.</strong>
            <span>It&rsquo;s measured by how fast you can coordinate, close a blind spot, filter the repeat noise, and ship the fix. Scoutgrid is built to make that measurement come out in your favor.</span>
            <p>Curious where your environment stands today? Talk to the Scoutgrid team about a readiness walkthrough.</p>
          </div>
        </div>
      </article>
    </PublicDemoShell>
  );
}

export function ZeroDayBlogPage() {
  return (
    <PublicDemoShell>
      <article className="blog-article">
        <header className="blog-article-header">
          <Link className="blog-back-link" to="/demo/blog">← All blogs</Link>
          <span className="blog-article-kicker">Scoutgrid Blog · Zero-Day Response</span>
          <h1>Zero-day response: from disclosure to remediation in hours, not weeks</h1>
          <p className="blog-article-deck">Fix Intelligence + AI-assisted investigation.</p>
          <time dateTime="2026-07-19">July 19, 2026</time>
        </header>

        <div className="blog-article-body">
          <p>
            A zero-day drops on a Monday morning. Within minutes, it&rsquo;s everywhere — security Twitter,
            vendor advisories, your Slack. But for most teams, the next few days aren&rsquo;t spent fixing
            anything. They&rsquo;re spent answering three questions: <em>Are we affected? Where? How bad is it?</em>
          </p>
          <p>
            That&rsquo;s the gap that matters most — not the moment a vulnerability is disclosed, but the days it
            takes a team to turn &ldquo;this exists&rdquo; into &ldquo;this is handled.&rdquo; Most of that time
            isn&rsquo;t urgency or effort. It&rsquo;s manual investigation: digging through systems, chasing owners,
            and rebuilding context that has to be assembled from scratch every single time.
          </p>

          <blockquote>
            The vulnerability isn&rsquo;t what costs you the most time. Figuring out what to do about it is.
          </blockquote>

          <section>
            <h2>What the slow path actually costs you</h2>
            <ul>
              <li><strong>Hours lost just scoping the blast radius.</strong> Analysts manually search for where an affected component lives — across teams, tickets, and spreadsheets that are already out of date.</li>
              <li><strong>Context rebuilt from scratch, every time.</strong> Understanding what a new vulnerability actually means for your environment means reading advisories, cross-referencing internal systems, and looping in the right owner — and doing it all again for the next one.</li>
              <li><strong>A severity score isn&rsquo;t a plan.</strong> Knowing something is &ldquo;critical&rdquo; doesn&rsquo;t tell your team what to do next, in what order, or how.</li>
              <li><strong>Days of investigation before a single hour of remediation.</strong> By the time the team has enough context to act with confidence, the exposure window has already cost you the time that mattered most.</li>
            </ul>
          </section>

          <section>
            <h2>How Scoutgrid closes the gap</h2>
            <p>
              Scoutgrid is built to collapse the distance between disclosure and action, so your team&rsquo;s time
              goes toward fixing things — not investigating them.
            </p>
            <ul>
              <li><strong>Instant answers, not hours of digging.</strong> The moment a new vulnerability matters to your environment, Scoutgrid tells you plainly what it affects, how exposed you are, and why it matters — in plain language, immediately.</li>
              <li><strong>A clear next step, not just a score.</strong> Instead of leaving your team to figure out what to do with a severity rating, Scoutgrid points directly at what to fix and how — turning a number into an actual plan.</li>
              <li><strong>Remediation starts sooner.</strong> The investigation work that used to take hours or days happens instantly, so your team moves straight to fixing — compressing the response timeline from weeks to hours.</li>
              <li><strong>Less tribal knowledge required.</strong> Your team doesn&rsquo;t need to be the world&rsquo;s foremost expert on every new vulnerability to respond well. Scoutgrid brings the context and the fix path directly to them.</li>
              <li><strong>Confidence under pressure.</strong> When a zero-day breaks, your team acts from a complete picture immediately — instead of racing to assemble one first.</li>
            </ul>
          </section>

          <aside className="blog-practice-callout">
            <strong>In practice</strong>
            <p>
              A zero-day is disclosed Monday morning. With the old approach, your team spends the rest of the
              week just figuring out exposure and next steps. With Scoutgrid, that same team has answers and a fix
              path before lunch — and remediation is already underway by end of day.
            </p>
          </aside>

          <section>
            <h2>The bigger picture</h2>
            <p>
              Zero-days aren&rsquo;t rare anymore — they&rsquo;re routine. The teams that come out ahead aren&rsquo;t
              the ones with the most headcount or the most dashboards. They&rsquo;re the ones who can go from
              &ldquo;this just happened&rdquo; to &ldquo;this is fixed&rdquo; the fastest. Scoutgrid is built to make
              that the normal outcome every time — not the exception on the days everything happens to go right.
            </p>
          </section>

          <aside className="blog-takeaways">
            <strong>Key takeaways</strong>
            <ul>
              <li>Response time is decided by investigation speed, not team size.</li>
              <li>A severity score without a fix path just shifts the work onto your team.</li>
              <li>Scoutgrid turns days of manual digging into minutes of clarity — and hours to remediation instead of weeks.</li>
            </ul>
          </aside>

          <div className="blog-closing-callout">
            <strong>Other tools tell you something bad happened.</strong>
            <span>Scoutgrid tells you what it means for you — and exactly what to do about it, in hours, not weeks.</span>
          </div>
        </div>
      </article>
    </PublicDemoShell>
  );
}

export function DemoRequestPage() {
  const navigate = useNavigate();
  const [formError, setFormError] = React.useState<{ field: 'terms' | 'email' | 'captcha'; message: string } | null>(null);
  const [captchaToken, setCaptchaToken] = React.useState<string | null>(null);
  const [captchaClearReason, setCaptchaClearReason] = React.useState<CaptchaClearReason | null>(null);
  const [captchaResetKey, setCaptchaResetKey] = React.useState(0);
  const handleCaptchaToken = React.useCallback((token: string | null, reason?: CaptchaClearReason) => {
    setCaptchaToken(token);
    setCaptchaClearReason(token ? null : reason ?? null);
  }, []);
  const requestDemo = useMutation({
    mutationFn: api.createDemoRequest,
    onSuccess: () => navigate('/demo/request/success'),
    onError: () => setCaptchaResetKey((current) => current + 1)
  });

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    const formData = new FormData(event.currentTarget);
    const acceptedTerms = formData.get('acceptedTerms') === 'on';
    if (!acceptedTerms) {
      setFormError({ field: 'terms', message: 'Accept the demo terms to request access.' });
      return;
    }
    const email = String(formData.get('email') ?? '').trim();
    if (!isCorporateEmail(email)) {
      setFormError({ field: 'email', message: 'Enter a valid corporate email address.' });
      return;
    }
    if (!captchaToken) {
      setFormError({ field: 'captcha', message: 'Complete the CAPTCHA verification before submitting.' });
      return;
    }
    requestDemo.mutate({
      fullName: String(formData.get('fullName') ?? '').trim(),
      email,
      company: String(formData.get('company') ?? '').trim(),
      roleTitle: String(formData.get('roleTitle') ?? '').trim(),
      companySize: String(formData.get('companySize') ?? '').trim(),
      notes: String(formData.get('notes') ?? '').trim(),
      acceptedTerms,
      captchaToken
    });
  };

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <div className="panel-header">
          <div>
            <h1>Request for product demo</h1>
            <div className="panel-caption">We review requests before provisioning an isolated 7-day workspace with the full guided product experience.</div>
          </div>
          <div className="panel-actions">
            <Link to="/demo">Back to overview</Link>
            <Link to="/login">Already have access? Log in</Link>
          </div>
        </div>
        <form className="demo-request-form" onSubmit={submit}>
          <label className="half-width">Full name<input name="fullName" autoComplete="name" required maxLength={255} /></label>
          <label className="half-width">Work email
            <input
              name="email"
              type="email"
              autoComplete="email"
              required
              maxLength={255}
              aria-invalid={formError?.field === 'email' || undefined}
              aria-describedby={formError?.field === 'email' ? 'demo-request-email-hint demo-request-error' : 'demo-request-email-hint'}
            />
            <span id="demo-request-email-hint" className="field-hint">Use your company email address. Personal email providers are not accepted.</span>
          </label>
          <label className="third-width">Company<input name="company" autoComplete="organization" required maxLength={255} /></label>
          <label className="third-width">Role<input name="roleTitle" autoComplete="organization-title" maxLength={255} /></label>
          <label className="third-width">Company size
            <select name="companySize" defaultValue="">
              <option value="" disabled>Select size</option>
              <option value="1-100">1-100</option>
              <option value="101-1000">101-1,000</option>
              <option value="1001-5000">1,001-5,000</option>
              <option value="5000+">5,000+</option>
            </select>
          </label>
          <label className="full-width">Notes<textarea name="notes" rows={3} maxLength={2000} /></label>
          <label className="demo-terms full-width">
            <input
              name="acceptedTerms"
              type="checkbox"
              aria-invalid={formError?.field === 'terms' || undefined}
              aria-describedby={formError?.field === 'terms' ? 'demo-request-error' : undefined}
            />
            <span>I understand the demo is time-boxed, uses isolated sample-friendly workflows, and may include demo-specific usage limits.</span>
          </label>
          <TurnstileWidget onTokenChange={handleCaptchaToken} resetKey={captchaResetKey} />
          {!captchaToken && (
            <p id="demo-request-captcha-status" className="field-hint full-width" role="status">
              {captchaClearReason === 'expired'
                ? 'The verification expired. Complete it again to submit your request.'
                : captchaClearReason === 'error'
                  ? 'The verification could not be completed. Retry the check above, or reload the page if it does not appear.'
                  : captchaClearReason === 'reset'
                    ? 'Your entries are kept. Complete the verification again to resubmit.'
                    : 'Complete the verification above to enable Submit request.'}
            </p>
          )}
          {(formError || requestDemo.isError) && (
            <div id="demo-request-error" className="notice error full-width" role="alert">
              {formError?.message ?? (requestDemo.error instanceof Error ? requestDemo.error.message : 'Demo request failed')}
            </div>
          )}
          <button
            className="btn btn-primary"
            type="submit"
            disabled={requestDemo.isPending || !captchaToken}
            aria-describedby={captchaToken ? undefined : 'demo-request-captcha-status'}
          >
            {requestDemo.isPending ? 'Submitting...' : 'Submit request'}
          </button>
        </form>
      </section>
    </PublicDemoShell>
  );
}

export function DemoRequestSuccessPage() {
  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Request received</h1>
        <p>We’ll review the request and send an invite link after the Scoutgrid demo workspace is provisioned with the full guided experience.</p>
        <Link className="btn btn-secondary" to="/demo">Back to demo overview</Link>
      </section>
    </PublicDemoShell>
  );
}

function usePrivateLink() {
  const location = useLocation();
  const [link] = React.useState(() => {
    const isCurrentLink = /^\/(invite|tenant-invite|setup)$/.test(location.pathname);
    const params = new URLSearchParams(isCurrentLink ? location.hash.slice(1) : '');
    // Remove bearer values before child effects, requests, or subsequent navigation.
    const cleanPath = '/' + location.pathname.split('/')[1];
    window.history.replaceState(window.history.state, '', cleanPath);
    return { token: params.get('token') ?? '', email: params.get('email') ?? '' };
  });
  return link;
}

/**
 * Next step for an unusable invite or setup link. Links only to routes that
 * exist; there is no self-service re-issue, so the copy names who can help.
 */
function AuthLinkRecovery({ message, requestDemo = false }: { message: string; requestDemo?: boolean }) {
  return (
    <div className="auth-link-recovery">
      <p>{message}</p>
      <div className="button-row">
        <Link className="btn btn-secondary" to="/login">Go to log in</Link>
        {requestDemo ? <Link className="btn btn-secondary" to="/demo/request">Request a demo</Link> : null}
      </div>
    </div>
  );
}

function DemoInviteRecovery() {
  return (
    <AuthLinkRecovery
      requestDemo
      message="Ask the Scoutgrid team to resend your invite, or submit a new demo request. If you already activated the workspace, log in with your email and password."
    />
  );
}

export function DemoInvitePage() {
  const { token } = usePrivateLink();
  const navigate = useNavigate();
  const inviteQuery = useQuery({
    queryKey: ['demo-invite', token],
    queryFn: () => api.validateDemoInvite(token),
    enabled: token.length > 0
  });
  const acceptInvite = useMutation({
    mutationFn: () => api.acceptDemoInvite(token),
    onSuccess: (response) => {
      if (response.status === 'ACCEPTED') {
        const nextParams = new URLSearchParams({
          setup: '1',
          email: response.email
        });
        navigate(`/login?${nextParams.toString()}`);
      }
    }
  });

  const invite = inviteQuery.data;
  const deliveryFailed = invite?.status === 'DELIVERY_ERROR';
  return (
    <PublicDemoShell compact authEntry>
      <section className="public-form-panel">
        <h1>Demo invite</h1>
        {!token ? (
          <>
            <div className="notice error" role="alert">This link has expired. Request a new invitation link.</div>
            <DemoInviteRecovery />
          </>
        ) : inviteQuery.isLoading ? (
          <p role="status">Checking invite...</p>
        ) : inviteQuery.isError ? (
          <>
            <div className="notice error" role="alert">{inviteQuery.error instanceof Error ? inviteQuery.error.message : 'Invite is invalid'}</div>
            <DemoInviteRecovery />
          </>
        ) : invite ? (
          <>
            <div className={`notice ${deliveryFailed ? 'error' : 'success'}`}>
              {invite.message}
            </div>
            {deliveryFailed && (
              <p>
                The workspace was provisioned, but Scoutgrid could not deliver the email automatically.
                You can still accept this invite and continue with manual password setup.
              </p>
            )}
            <dl className="demo-invite-details">
              <div><dt>Workspace</dt><dd>{invite.tenantName}</dd></div>
              <div><dt>Email</dt><dd>{invite.email}</dd></div>
              <div><dt>Demo expires</dt><dd>{new Date(invite.demoExpiresAt).toLocaleString()}</dd></div>
            </dl>
            <div className="button-row">
              <button
                className="btn btn-primary"
                type="button"
                disabled={!invite.valid || acceptInvite.isPending}
                onClick={() => acceptInvite.mutate()}
              >
                {acceptInvite.isPending ? 'Activating...' : 'Activate your workspace'}
              </button>
            </div>
            {acceptInvite.isError && <div className="notice error" role="alert">{acceptInvite.error instanceof Error ? acceptInvite.error.message : 'Accept failed'}</div>}
          </>
        ) : null}
      </section>
    </PublicDemoShell>
  );
}

export function TenantInvitePage() {
  const { token } = usePrivateLink();
  const navigate = useNavigate();
  const inviteQuery = useQuery({
    queryKey: ['tenant-invite', token],
    queryFn: () => api.validateTenantInvite(token),
    enabled: token.length > 0
  });
  const acceptInvite = useMutation({
    mutationFn: () => api.acceptTenantInvite(token),
    onSuccess: (response) => {
      if (response.status === 'ACCEPTED') {
        const nextParams = new URLSearchParams({
          setup: '1',
          email: response.email
        });
        navigate(`/login?${nextParams.toString()}`);
      }
    }
  });

  const invite = inviteQuery.data;
  const deliveryFailed = invite?.status === 'DELIVERY_ERROR';

  return (
    <PublicDemoShell compact authEntry>
      <section className="public-form-panel">
        <h1>Workspace invite</h1>
        {!token ? (
          <>
            <div className="notice error" role="alert">This link has expired. Request a new invitation link.</div>
            <AuthLinkRecovery message="Ask your workspace administrator to send a new invite. If you already accepted it, log in with your email and password." />
          </>
        ) : inviteQuery.isLoading ? (
          <p role="status">Checking invite...</p>
        ) : inviteQuery.isError ? (
          <>
            <div className="notice error" role="alert">{inviteQuery.error instanceof Error ? inviteQuery.error.message : 'Invite is invalid'}</div>
            <AuthLinkRecovery message="Ask your workspace administrator to send a new invite. If you already accepted it, log in with your email and password." />
          </>
        ) : invite ? (
          <>
            <div className={`notice ${deliveryFailed ? 'error' : 'success'}`}>
              {invite.message}
            </div>
            {deliveryFailed ? (
              <p>The automatic email delivery failed, but this invite link is still valid.</p>
            ) : null}
            <dl className="demo-invite-details">
              <div><dt>Workspace</dt><dd>{invite.tenantName}</dd></div>
              <div><dt>Email</dt><dd>{invite.email}</dd></div>
              <div><dt>Role</dt><dd>{invite.role.replace(/_/g, ' ')}</dd></div>
              <div><dt>Invite expires</dt><dd>{new Date(invite.inviteExpiresAt).toLocaleString()}</dd></div>
            </dl>
            <div className="button-row">
              <button
                className="btn btn-primary"
                type="button"
                disabled={!invite.valid || acceptInvite.isPending}
                onClick={() => acceptInvite.mutate()}
              >
                {acceptInvite.isPending ? 'Activating...' : 'Accept invite'}
              </button>
            </div>
            {acceptInvite.isError ? <div className="notice error" role="alert">{acceptInvite.error instanceof Error ? acceptInvite.error.message : 'Accept failed'}</div> : null}
          </>
        ) : null}
      </section>
    </PublicDemoShell>
  );
}

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const setupMode = searchParams.get('setup') === '1';
  const loginEmailParam = searchParams.get('email') ?? '';
  const activationComplete = searchParams.get('activated') === '1';
  const [email, setEmail] = React.useState(loginEmailParam);
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const personasQuery = useQuery({
    queryKey: ['login-test-personas'],
    queryFn: api.listTestPersonas,
    enabled: TEST_PERSONAS_ENABLED
  });

  const nextPath = searchParams.get('next');
  const navigateAfterAuth = React.useCallback((actor: ActorContext) => {
    if (nextPath?.startsWith('/') && !nextPath.startsWith('//') && !nextPath.includes('\\') && !nextPath.startsWith('/login')) {
      navigate(nextPath, { replace: true });
      return;
    }
    if (actor.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER') && actor.platformScope) {
      navigate('/platform/tenants', { replace: true });
      return;
    }
    if (canManageRiskPolicy(actor)) {
      navigate('/configurations', { replace: true });
      return;
    }
    if (actor.demo === true && canManageInventorySources(actor)) {
      navigate(pathForConnectView('sources'), { replace: true });
      return;
    }
    navigate('/exposure', { replace: true });
  }, [navigate, nextPath]);

  React.useEffect(() => {
    setEmail(loginEmailParam);
  }, [loginEmailParam]);

  const applyToken = React.useCallback(async (token: string) => {
    queryClient.clear();
    setStoredAuthToken(token);
    const actor = await api.getAuthContext();
    queryClient.setQueryData(getAuthContextQueryKey(token), actor);
    navigateAfterAuth(actor);
  }, [navigateAfterAuth, queryClient]);

  const loginMutation = useMutation({
    mutationFn: async () => {
      const response = await api.login(email, password);
      await applyToken(response.token);
      return response;
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Login failed');
    }
  });

  const setupPasswordMutation = useMutation({
    mutationFn: async () => {
      if (!setupMode) {
        throw new Error('Password setup session is missing');
      }
      return api.setupPassword(password);
    },
    onSuccess: () => {
      const nextParams = new URLSearchParams({ activated: '1' });
      if (loginEmailParam.trim()) {
        nextParams.set('email', loginEmailParam.trim());
      }
      navigate(`/login?${nextParams.toString()}`, { replace: true });
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Password setup failed');
    }
  });

  const issuePersonaToken = useMutation({
    mutationFn: async (personaKey: string) => {
      const response = await api.issueTestPersonaToken(personaKey);
      await applyToken(response.token);
      return response;
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Test persona login failed');
    }
  });

  const submitLogin = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (setupMode) {
      setupPasswordMutation.mutate();
      return;
    }
    loginMutation.mutate();
  };

  return (
    <PublicDemoShell compact authEntry>
      <section className="public-form-panel">
        <h1>Log in to Scoutgrid</h1>
        <p>
          {setupMode
            ? 'Set a password for your SG account. After saving it, return to the login screen and sign in with your email and new password.'
            : 'Use your email and password to access your tenant workspace or the platform console.'}
        </p>
        {!setupMode && activationComplete && (
          <div className="notice success" role="status">
            Password created successfully. Sign in with your email and new password to continue.
          </div>
        )}
        {!setupMode && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            <label>Email<input type="email" name="email" autoComplete="username" spellCheck={false} value={email} onChange={(event) => setEmail(event.target.value)} /></label>
            <PasswordInput label="Password" autoComplete="current-password" value={password} onChange={setPassword} />
            <button className="btn btn-primary" type="submit" disabled={loginMutation.isPending || !email.trim() || !password.trim()}>
              {loginMutation.isPending ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        )}
        {setupMode && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            {loginEmailParam.trim() ? <p>Account: {loginEmailParam.trim()}</p> : null}
            <PasswordInput
              label="New password"
              autoComplete="new-password"
              describedBy="setup-password-requirement"
              value={password}
              onChange={setPassword}
            />
            <span id="setup-password-requirement" className="field-hint">
              Use at least {MIN_SETUP_PASSWORD_LENGTH} characters.
            </span>
            <button className="btn btn-primary" type="submit" disabled={setupPasswordMutation.isPending || password.trim().length < MIN_SETUP_PASSWORD_LENGTH}>
              {setupPasswordMutation.isPending ? 'Saving...' : 'Set password'}
            </button>
          </form>
        )}
        {error && <div className="notice error" role="alert">{error}</div>}
        {!setupMode && (
          <p className="field-hint">
            There is no self-service password reset. If you cannot sign in, ask your workspace administrator, or the Scoutgrid team for a demo workspace, for a new setup link.
          </p>
        )}
        {TEST_PERSONAS_ENABLED && (
          <div className="section-block">
            <h2 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Non-production test personas</h2>
            {personasQuery.isLoading ? (
              <p>Loading personas...</p>
            ) : personasQuery.isError ? (
              <div className="notice error" role="alert">
                {personasQuery.error instanceof Error ? personasQuery.error.message : 'Failed to load personas'}
              </div>
            ) : (
              <div className="button-row">
                {(personasQuery.data ?? []).map((persona) => (
                  <button
                    key={persona.key}
                    className="btn btn-secondary"
                    type="button"
                    onClick={() => {
                      setError(null);
                      issuePersonaToken.mutate(persona.key);
                    }}
                    disabled={issuePersonaToken.isPending}
                  >
                    {persona.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </PublicDemoShell>
  );
}

export function SetupSessionPage() {
  const { token, email } = usePrivateLink();
  const navigate = useNavigate();
  const [error, setError] = React.useState<string | null>(null);
  const exchangePromiseRef = React.useRef<Promise<void> | null>(null);

  React.useEffect(() => {
    if (!token) {
      setError('Password setup link is invalid or expired.');
      return;
    }
    if (!exchangePromiseRef.current) {
      window.history.replaceState(window.history.state, '', '/login?setup=pending');
      exchangePromiseRef.current = api.startPasswordSetupSession(token);
    }
    let active = true;
    void exchangePromiseRef.current
      .then(() => {
        if (!active) return;
        const nextParams = new URLSearchParams({ setup: '1' });
        if (email.trim()) nextParams.set('email', email.trim());
        navigate(`/login?${nextParams.toString()}`, { replace: true });
      })
      .catch((setupError) => {
        if (!active) return;
        setError(setupError instanceof Error ? setupError.message : 'Password setup link is invalid or expired.');
      });
    return () => {
      active = false;
    };
  }, [navigate, email, token]);

  return (
    <PublicDemoShell compact authEntry>
      <section className="public-form-panel">
        <h1>Preparing password setup</h1>
        {error ? (
          <>
            <div className="notice error" role="alert">{error}</div>
            <AuthLinkRecovery message="Setup links work once. Ask your workspace administrator for a new setup link, or log in if you already set your password." />
          </>
        ) : <p role="status">Securing your one-time setup session...</p>}
      </section>
    </PublicDemoShell>
  );
}

export function DemoExpiredPage() {
  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Demo expired</h1>
        <p>This 7-day demo workspace is no longer active. Contact the team if you need more time or want to continue validation.</p>
        <Link className="btn btn-primary" to="/demo/request">Request another demo</Link>
      </section>
    </PublicDemoShell>
  );
}
