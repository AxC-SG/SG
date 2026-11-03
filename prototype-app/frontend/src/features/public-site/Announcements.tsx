import { Link } from 'react-router-dom';
import { BrandMark } from '../../components/BrandMark';
import { PublicDemoShell, SITE_NAME } from './PublicSiteShell';

export const NVIDIA_INCEPTION_PATH = '/demo/announcements/scoutgrid-joins-nvidia-inception';

// Co-branded lockup per NVIDIA's partner guidance: horizontal arrangement, partner
// (Scoutgrid) first, NVIDIA second, a divider line between them and equal visual weight.
export function NvidiaCoBrandLockup({ size = 'md' }: { size?: 'sm' | 'md' }) {
  return (
    <div className={`sgw-cobrand sgw-cobrand--${size}`} role="img" aria-label={`${SITE_NAME} and NVIDIA`}>
      <span className="sgw-cobrand-partner" aria-hidden="true">
        <BrandMark className="sgw-cobrand-mark" />
        <span className="sgw-cobrand-word">{SITE_NAME}</span>
      </span>
      <span className="sgw-cobrand-divider" aria-hidden="true" />
      <img className="sgw-cobrand-nvidia" src="/brand/nvidia-logo-horizontal.png" alt="" width="1200" height="249" />
    </div>
  );
}

export function AnnouncementsIndexPage() {
  return (
    <PublicDemoShell>
      <div className="blog-index-page">
        <header className="blog-hero">
          <div className="blog-page-width">
            <span className="blog-hero-eyebrow">Resources</span>
            <h1>Announcements</h1>
            <p>News and milestones from the {SITE_NAME} team.</p>
          </div>
        </header>

        <section className="blog-list blog-page-width sgw-announcement-list" aria-label={`${SITE_NAME} announcements`}>
          <article className="blog-card sgw-announcement-card">
            <div className="sgw-announcement-card-art">
              <NvidiaCoBrandLockup size="sm" />
            </div>
            <time dateTime="2026-11-03">November 3, 2026</time>
            <h2>
              <Link to={NVIDIA_INCEPTION_PATH}>Scoutgrid joins the NVIDIA Inception program</Link>
            </h2>
            <p>
              Scoutgrid has been accepted into NVIDIA Inception, the program for startups building with AI, as we
              help enterprises secure AI in the context of their whole exposure.
            </p>
            <Link className="blog-read-more" to={NVIDIA_INCEPTION_PATH}>
              Read more <span aria-hidden="true">→</span>
            </Link>
          </article>
        </section>
      </div>
    </PublicDemoShell>
  );
}

export function NvidiaInceptionAnnouncementPage() {
  return (
    <PublicDemoShell>
      <article className="blog-article sgw-announcement">
        <header className="blog-article-header">
          <Link className="blog-back-link" to="/demo/announcements">← All announcements</Link>
          <span className="blog-article-kicker">{SITE_NAME} · Announcement</span>
          <h1>Scoutgrid joins the NVIDIA Inception program</h1>
          <p className="blog-article-deck">
            Scoutgrid has been accepted into NVIDIA Inception, giving the team access to NVIDIA&rsquo;s technology,
            expertise and ecosystem as it builds AI-first exposure management.
          </p>
          <time dateTime="2026-11-03">November 3, 2026 · Announced by the {SITE_NAME} team</time>
        </header>

        <figure className="sgw-announcement-art">
          <NvidiaCoBrandLockup />
        </figure>

        <div className="blog-article-body">
          <p>
            Hyderabad, India — {SITE_NAME} today announced that it has joined NVIDIA Inception, a program that
            supports startups building with AI, data science and accelerated computing. The program gives{' '}
            {SITE_NAME} access to NVIDIA technical resources and training, and to a global community of AI
            innovators, as it expands the AI Grid and the wider {SITE_NAME} platform.
          </p>

          <section>
            <h2>Securing AI in context</h2>
            <p>
              Enterprises are moving AI into production faster than their security programs can follow. Models,
              agents, knowledge bases and MCP servers now sit alongside the infrastructure, software supply chain and
              cloud services they depend on, and risk in any one of them affects the others.
            </p>
            <p>
              {SITE_NAME} brings that picture together in four Grids. The AI Grid discovers and assesses AI assets and
              their exposure. The Infra, BOM and Cloud Grids connect it to the hosts, dependencies (SBOM, AI-BOM and
              CBOM) and cloud resources around it, so security teams see the whole exposure, not just the AI
              technology itself.
            </p>
          </section>

          <section>
            <h2>What Inception brings</h2>
            <ul>
              <li><strong>Technology and expertise.</strong> Access to NVIDIA technical resources and guidance as we build for the AI era.</li>
              <li><strong>Training.</strong> NVIDIA learning resources for the team as AI workloads and tooling evolve.</li>
              <li><strong>Ecosystem.</strong> A connection to NVIDIA&rsquo;s worldwide network of AI startups, partners and customers.</li>
            </ul>
          </section>

          <section>
            <h2>What&rsquo;s next</h2>
            <p>With the program&rsquo;s support, {SITE_NAME} will keep extending the platform:</p>
            <ul>
              <li>broader AI Grid discovery and posture assessment across AI platforms, agents and MCP servers;</li>
              <li>deeper AI-BOM visibility into the models, datasets and dependencies behind each AI system;</li>
              <li>faster, connected exposure analysis that links AI risk to the infrastructure, software and cloud around it.</li>
            </ul>
          </section>

          <div className="blog-closing-callout">
            <strong>See Scoutgrid in action.</strong>
            <span>Explore the AI Grid and the wider platform in a private demo, tailored to your priorities.</span>
            <p><Link className="sgw-btn sgw-btn-red" to="/demo/request">Request a demo</Link></p>
          </div>
        </div>
      </article>
    </PublicDemoShell>
  );
}
