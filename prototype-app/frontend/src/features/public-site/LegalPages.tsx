import React from 'react';
import { Link } from 'react-router-dom';
import { PublicDemoShell, SITE_NAME } from './PublicSiteShell';

// Legal text for the public site. It describes how Scoutgrid actually behaves (essential
// storage only, no analytics or advertising trackers) and still needs review by qualified
// counsel before the site goes live.
const COMPANY = SITE_NAME;
const ADDRESS = 'Hyderabad, India';
const CONTACT_EMAIL = 'support@scoutgrid.io';
const GOVERNING_LAW = 'India';
const JURISDICTION = 'Hyderabad, Telangana, India';
const LAST_UPDATED = '3 November 2026';

function EmailLink() {
  return <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>;
}

function LegalArticle({ kicker, title, deck, children }: { kicker: string; title: string; deck: string; children: React.ReactNode }) {
  return (
    <PublicDemoShell>
      <article className="blog-article sgw-legal">
        <header className="blog-article-header">
          <span className="blog-article-kicker">{kicker}</span>
          <h1>{title}</h1>
          <p className="blog-article-deck">{deck}</p>
          <time dateTime="2026-11-03">Last updated: {LAST_UPDATED}</time>
        </header>
        <div className="blog-article-body">{children}</div>
      </article>
    </PublicDemoShell>
  );
}

export function PrivacyPolicyPage() {
  return (
    <LegalArticle
      kicker={`${SITE_NAME} · Legal`}
      title="Privacy Policy"
      deck={`How ${COMPANY} (“we”, “us”) collects, uses and protects personal information when you visit this site, request a demo or sign in to the ${SITE_NAME} platform.`}
    >
      <section>
        <h2>1. Scope and our role</h2>
        <p>This policy applies to scoutgrid.io, the {SITE_NAME} blog, demo requests, account sign-in and our direct communications with you. For this information, {COMPANY} decides why and how it is used (we act as the data controller or data fiduciary).</p>
        <p>It does not cover the data your organization loads into its {SITE_NAME} workspace, such as software and AI bills of materials (SBOM, AI-BOM, CBOM), asset and CMDB inventories, cloud and AI discovery results, vulnerability findings and connector settings. We process that customer data only on your organization&rsquo;s instructions, under its agreement with us, and your organization remains responsible for it.</p>
      </section>

      <section>
        <h2>2. Information we collect</h2>
        <ul>
          <li><strong>Demo-request details.</strong> Your name, work email address, company, role, company size and any notes you include. We accept company email addresses only; personal email providers are rejected.</li>
          <li><strong>Account and login data.</strong> Your email address, a securely hashed password (we never store it in readable form), workspace membership and role, invitation and password-setup records, and a log of sign-in and administrative activity.</li>
          <li><strong>Product usage and telemetry.</strong> Technical information needed to run and secure the service, such as IP address, browser and device type, request logs, performance measurements and error reports.</li>
          <li><strong>Communications.</strong> Messages you send us, for example support requests or replies to demo and invitation emails.</li>
          <li><strong>Cookies and similar technologies.</strong> A small number of strictly necessary cookies and browser-storage entries. See our <Link to="/demo/cookies">Cookie Policy</Link>.</li>
        </ul>
        <p>We do not knowingly collect sensitive personal information, such as health, biometric or financial account data, through this site.</p>
      </section>

      <section>
        <h2>3. Where it comes from</h2>
        <ul>
          <li>From you, when you request a demo, sign in, set a password or contact us.</li>
          <li>From your organization, when a workspace administrator invites you or assigns you a role.</li>
          <li>Automatically, from your browser and device when you use the site or the platform.</li>
        </ul>
      </section>

      <section>
        <h2>4. How we use it, and our legal basis</h2>
        <ul>
          <li><strong>To review demo requests and provision demo workspaces</strong>, because you asked us to (steps before a contract) or our legitimate interest in responding to business enquiries.</li>
          <li><strong>To create accounts, authenticate users and run the service</strong>, to perform our contract with you or your organization.</li>
          <li><strong>To secure the service</strong>, including preventing spam, fraud and abuse with a CAPTCHA check and keeping audit logs, based on our legitimate interests and legal obligations.</li>
          <li><strong>To fix errors and improve reliability</strong>, based on our legitimate interest in a working, secure product.</li>
          <li><strong>To send service messages</strong>, such as invitations, password-setup links and important notices, to perform our contract.</li>
          <li><strong>To send product news</strong>, only with your consent where the law requires it. Every such email lets you unsubscribe.</li>
          <li><strong>To meet legal obligations</strong>, such as accounting, tax and responding to lawful requests.</li>
        </ul>
        <p>Where we rely on consent, you can withdraw it at any time. We do not use your personal information for automated decisions that have legal or similarly significant effects on you.</p>
      </section>

      <section>
        <h2>5. Sharing and processors</h2>
        <p>We do not sell personal information or share it for advertising. We share it only with:</p>
        <ul>
          <li><strong>Service providers that process it for us under contract</strong>: cloud hosting and databases, transactional email delivery, CAPTCHA and bot protection (Cloudflare Turnstile), error monitoring (configured to exclude personal details by default), and web font delivery (Google Fonts).</li>
          <li><strong>Your organization&rsquo;s administrators</strong>, who can see the members, roles and activity of their workspace.</li>
          <li><strong>Professional advisers</strong>, such as lawyers and auditors, under confidentiality duties.</li>
          <li><strong>Authorities</strong>, where the law requires it or to protect rights, property or safety.</li>
          <li><strong>A buyer or successor</strong>, in a merger, acquisition or similar transaction, subject to this policy.</li>
        </ul>
        <p>Access to customer workspaces by {SITE_NAME} staff for support happens only through a support grant that your organization approves, and is recorded in your audit log.</p>
      </section>

      <section>
        <h2>6. Retention</h2>
        <ul>
          <li><strong>Demo workspaces</strong> are time-limited, normally to 7 days, and are removed after they expire.</li>
          <li><strong>Demo requests</strong> are kept while we review and follow up on them, and for a limited period afterwards for record keeping.</li>
          <li><strong>Account data and audit logs</strong> are kept for the life of the account and then for as long as needed for security, dispute and legal purposes.</li>
          <li><strong>Password-setup links and cookies</strong> expire after a short time, by default 30 minutes.</li>
        </ul>
        <p>When information is no longer needed, we delete or anonymize it, unless the law requires us to keep it longer.</p>
      </section>

      <section>
        <h2>7. Security</h2>
        <p>{SITE_NAME} is a security product, and we apply the same discipline to our own systems. Measures include encryption in transit, hashed passwords, encrypted and write-only storage of connector credentials, role-based access control, a separate database schema for each customer workspace, row-level security, and audit logging of sensitive actions. No method of transmission or storage is completely secure, so we cannot guarantee absolute security. If you believe you have found a vulnerability, please report it to <EmailLink />.</p>
      </section>

      <section>
        <h2>8. Your rights and how to contact us</h2>
        <p>Depending on where you live, you may have the right to access your personal information, correct or update it, ask us to erase it, restrict or object to its use, receive it in a portable format, withdraw consent, and nominate another person to exercise your rights. You also have the right to have a complaint handled by us and, if you are not satisfied, to complain to your data-protection authority.</p>
        <p>To make a request or raise a grievance, email <EmailLink /> or write to {COMPANY}, {ADDRESS}. We may need to verify your identity before acting on a request. If your account belongs to an organization&rsquo;s workspace, we may refer your request to that organization.</p>
      </section>

      <section>
        <h2>9. Regional information</h2>
        <p><strong>India.</strong> We process digital personal data in line with the Digital Personal Data Protection Act, 2023 and applicable rules. Grievances can be sent to <EmailLink />; you may escalate an unresolved grievance to the Data Protection Board of India.</p>
        <p><strong>European Economic Area, Switzerland and the United Kingdom.</strong> Where the GDPR or UK GDPR applies, the legal bases in section 4 apply, and you may complain to your local supervisory authority.</p>
        <p><strong>Other regions.</strong> We handle personal information in line with the local laws that apply to you.</p>
      </section>

      <section>
        <h2>10. International transfers</h2>
        <p>{SITE_NAME} is based in India, and our service providers may process information in other countries. Where the law requires it, we put appropriate safeguards in place for these transfers, such as standard contractual clauses.</p>
      </section>

      <section>
        <h2>11. Children</h2>
        <p>{SITE_NAME} is a business service and is not directed at anyone under 18. We do not knowingly collect personal information from children. If you believe a child has given us personal information, contact us and we will delete it.</p>
      </section>

      <section>
        <h2>12. Links to other sites</h2>
        <p>This site may link to other websites and services, such as social networks or vendor documentation. Their own privacy policies apply, and we are not responsible for them.</p>
      </section>

      <section>
        <h2>13. Changes to this policy</h2>
        <p>We may update this policy from time to time. We will post the updated version on this page and change the date below. If changes are significant, we will take reasonable steps to let you know.</p>
      </section>

      <section>
        <h2>14. Effective date</h2>
        <p>This policy is effective as of {LAST_UPDATED}. If it is translated, the English version prevails. See also our <Link to="/demo/cookies">Cookie Policy</Link> and <Link to="/demo/terms">Terms of Service</Link>.</p>
      </section>
    </LegalArticle>
  );
}

const ESSENTIAL_STORAGE: Array<{ name: string; type: string; purpose: string; duration: string }> = [
  { name: 'Sign-in token', type: 'Browser local storage', purpose: 'Keeps you signed in to your workspace.', duration: 'Until you log out or the token expires' },
  { name: 'XSRF-TOKEN', type: 'First-party cookie', purpose: 'Protects forms and account actions against cross-site request forgery.', duration: 'Browser session' },
  { name: 'scout_setup_session', type: 'First-party cookie (HttpOnly, Secure, SameSite=Strict)', purpose: 'Links a password-setup or invitation step to your browser.', duration: 'Up to 30 minutes by default' },
  { name: 'Cloudflare Turnstile', type: 'Third-party check on the demo-request form', purpose: 'Tells people from automated bots without a puzzle.', duration: 'Managed by Cloudflare' }
];

const PREFERENCE_STORAGE: Array<{ name: string; type: string; purpose: string; duration: string }> = [
  { name: 'scoutai-theme', type: 'Browser local storage', purpose: 'Remembers light or dark theme.', duration: 'Until you clear site data' },
  { name: 'Table and filter preferences', type: 'Browser local storage', purpose: 'Remembers columns, filters and views you choose in the platform.', duration: 'Until you clear site data' }
];

function StorageTable({ caption, rows }: { caption: string; rows: typeof ESSENTIAL_STORAGE }) {
  return (
    <div className="sgw-legal-table" role="region" aria-label={caption} tabIndex={0}>
      <table>
        <caption>{caption}</caption>
        <thead>
          <tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Purpose</th><th scope="col">Duration</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name}><th scope="row">{row.name}</th><td>{row.type}</td><td>{row.purpose}</td><td>{row.duration}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CookiePolicyPage() {
  return (
    <LegalArticle
      kicker={`${SITE_NAME} · Legal`}
      title="Cookie Policy"
      deck={`The cookies and similar technologies ${COMPANY} uses on scoutgrid.io and in the ${SITE_NAME} platform, and the choices you have.`}
    >
      <section>
        <h2>1. What these technologies are</h2>
        <p><strong>Cookies</strong> are small text files a website stores in your browser. <strong>Browser storage</strong> (local storage) works in a similar way and keeps small values on your device. <strong>Third-party scripts</strong> are code from another provider that runs on a page, such as a CAPTCHA check.</p>
      </section>

      <section>
        <h2>2. What Scoutgrid uses</h2>
        <p>We keep this deliberately small. We use only what is needed to run, secure and remember your settings for the service. We do <strong>not</strong> use analytics, advertising, cross-site tracking or session-replay cookies, and we do not sell or share cookie data for advertising.</p>
        <h3>Strictly necessary</h3>
        <p>These are required for sign-in, security and the demo-request form, so they cannot be switched off in our site.</p>
        <StorageTable caption="Strictly necessary cookies and storage" rows={ESSENTIAL_STORAGE} />
        <h3>Preferences</h3>
        <p>These remember choices you make. They stay on your device and are not sent to us for tracking.</p>
        <StorageTable caption="Preference storage" rows={PREFERENCE_STORAGE} />
      </section>

      <section>
        <h2>3. Other third-party services</h2>
        <ul>
          <li><strong>Google Fonts.</strong> The site loads its typefaces from Google, so your browser sends your IP address to Google when a page loads. Google Fonts does not set cookies.</li>
          <li><strong>Error monitoring.</strong> When enabled, the platform reports technical errors so we can fix them. It is configured to exclude personal details by default and does not set tracking cookies.</li>
        </ul>
      </section>

      <section>
        <h2>4. Your choices</h2>
        <p>Because we use only strictly necessary technologies and preferences, we do not show a cookie banner. If we ever add analytics or other non-essential cookies, we will ask for your consent first wherever the law requires it, and update this policy.</p>
        <p>You can block or delete cookies and site data in your browser settings (for example in Chrome, Firefox, Safari or Edge). These settings apply to each browser and device separately. If you block strictly necessary cookies or storage, sign-in and the demo-request form will not work.</p>
        <p>Our site does not currently respond to “Do Not Track” browser signals, because we do not track you across sites.</p>
      </section>

      <section>
        <h2>5. Changes and contact</h2>
        <p>We will update this policy and the date below when the technologies we use change. Questions can be sent to <EmailLink /> or to {COMPANY}, {ADDRESS}. Our <Link to="/demo/privacy">Privacy Policy</Link> explains how we handle personal information more generally.</p>
        <p>Effective as of {LAST_UPDATED}.</p>
      </section>
    </LegalArticle>
  );
}

export function TermsOfServicePage() {
  return (
    <LegalArticle
      kicker={`${SITE_NAME} · Legal`}
      title="Terms of Service"
      deck={`The terms that apply when you use this site, request a demo or access the ${SITE_NAME} platform provided by ${COMPANY}, ${ADDRESS}.`}
    >
      <section>
        <h2>1. Acceptance</h2>
        <p>By accessing this site or using the service, you agree to these terms. If you use the service on behalf of an organization, you confirm that you are authorized to accept these terms for it. If a separate written agreement covers your use, that agreement takes precedence.</p>
      </section>

      <section>
        <h2>2. The service and demo access</h2>
        <p>{SITE_NAME} provides AI security and exposure management software across its AI, Infra, BOM and Cloud Grids. Demo workspaces are granted at our discretion after review, are time-limited (normally 7 days), may use sample data and usage limits, and may be changed, suspended or ended at any time. Demo access is for evaluation only and not for production use.</p>
      </section>

      <section>
        <h2>3. Accounts and acceptable use</h2>
        <p>You are responsible for keeping your credentials confidential and for activity under your account. You must not:</p>
        <ul>
          <li>access the service without authorization, or attempt to bypass its security, tenant isolation or usage limits;</li>
          <li>upload unlawful content, malware or data you have no right to use;</li>
          <li>connect cloud accounts, repositories or systems that you are not authorized to assess, or use the service to attack or scan third-party systems;</li>
          <li>reverse engineer the service, except where the law allows it; or</li>
          <li>resell or provide the service to third parties without our agreement.</li>
        </ul>
      </section>

      <section>
        <h2>4. Customer data and confidentiality</h2>
        <p>Your organization keeps all rights to the data it provides, including bills of materials, inventories, discovery results and findings (“customer data”). You grant us the rights needed to host and process customer data solely to provide and support the service. You are responsible for having the right to provide customer data and for the access you grant through connectors. Each party will protect the other&rsquo;s confidential information with reasonable care and use it only for the purposes of this relationship. Our handling of personal information is described in our <Link to="/demo/privacy">Privacy Policy</Link>.</p>
      </section>

      <section>
        <h2>5. Intellectual property</h2>
        <p>The service, site, software, documentation and the {SITE_NAME} name and logo are owned by {COMPANY} or its licensors. Except for the limited right to use the service under these terms, no rights are granted to you. Feedback you choose to give may be used without obligation.</p>
      </section>

      <section>
        <h2>6. Third-party services</h2>
        <p>The service can connect to third-party products and data sources that you choose to configure, such as cloud providers, code repositories, CMDB, ticketing and patch-management tools. Your use of them is governed by their own terms, and we are not responsible for third-party services or their data.</p>
      </section>

      <section>
        <h2>7. Disclaimers and limitation of liability</h2>
        <p>The site and demo access are provided “as is” and “as available”, without warranties of any kind, to the extent permitted by law. Risk scores, findings and remediation recommendations, including any that are AI-assisted, support but do not replace your own security judgment, and we do not guarantee that the service will find every vulnerability or exposure.</p>
        <p>To the extent permitted by law, {COMPANY} will not be liable for indirect, incidental, special, consequential or punitive damages, or for lost profits, revenue or data. Our total liability arising from these terms will not exceed the amounts you paid for the service in the twelve months before the claim, or one hundred US dollars if you paid nothing.</p>
      </section>

      <section>
        <h2>8. Termination</h2>
        <p>You may stop using the service at any time. We may suspend or end access if you breach these terms, if required by law, or when a demo period ends. Sections that by their nature should survive termination will survive.</p>
      </section>

      <section>
        <h2>9. Governing law</h2>
        <p>These terms are governed by the laws of {GOVERNING_LAW}, without regard to conflict-of-laws rules. The courts at {JURISDICTION} have exclusive jurisdiction over disputes, unless applicable law requires otherwise.</p>
      </section>

      <section>
        <h2>10. Changes</h2>
        <p>We may update these terms from time to time. We will post the updated version on this page and change the date below. Continued use after changes take effect means you accept them. If these terms are translated, the English version prevails.</p>
      </section>

      <section>
        <h2>11. Contact</h2>
        <p>Questions about these terms can be sent to <EmailLink /> or to {COMPANY}, {ADDRESS}.</p>
        <p>Effective as of {LAST_UPDATED}.</p>
      </section>
    </LegalArticle>
  );
}
