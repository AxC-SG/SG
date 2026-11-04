import React from 'react';
import { DemoRequestForm } from '../../pages/DemoPublicPages';
import { PublicDemoShell, SITE_NAME } from './PublicSiteShell';

const CONTACT_EMAIL = 'sales@scoutgrid.io';

// There is no backend endpoint for these forms yet, so submitting opens the visitor's
// email client with the details filled in, addressed to the Scoutgrid team.
function openMail(subject: string, fields: Array<[string, string]>) {
  const body = fields.map(([label, value]) => `${label}: ${value}`).join('\n');
  window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

function formValue(form: HTMLFormElement, name: string) {
  return String(new FormData(form).get(name) ?? '').trim();
}

function PageHero({ eyebrow, title, children }: { eyebrow: string; title: string; children: React.ReactNode }) {
  return (
    <header className="blog-hero">
      <div className="blog-page-width">
        <span className="blog-hero-eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{children}</p>
      </div>
    </header>
  );
}

const PARTNER_TYPES = [
  { title: 'Security consultancies', body: 'Advisory and assessment firms helping clients understand and reduce exposure.' },
  { title: 'Resellers and integrators', body: 'Teams that bring security tooling to enterprise customers and run the rollout.' },
  { title: 'Managed security providers', body: 'Service providers who want to offer exposure management as part of their service.' },
  { title: 'Technology partners', body: 'Platforms and vendors whose products work alongside Scoutgrid for joint customers.' }
];

export function PartnersPage() {
  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    openMail(`Partner enquiry from ${formValue(form, 'organization')}`, [
      ['Name', formValue(form, 'fullName')],
      ['Work email', formValue(form, 'email')],
      ['Organization', formValue(form, 'organization')],
      ['Partner type', formValue(form, 'partnerType')],
      ['Regions and markets', formValue(form, 'regions')],
      ['How we could work together', formValue(form, 'message')]
    ]);
  };

  return (
    <PublicDemoShell>
      <div className="blog-index-page sgw-company-page">
        <PageHero eyebrow="Company" title="Partners">
          Work with {SITE_NAME} to help enterprises see and reduce their whole exposure, from AI to infrastructure.
        </PageHero>

        <section className="blog-page-width sgw-company-section" aria-labelledby="partner-types">
          <h2 id="partner-types">Who we work with</h2>
          <div className="sgw-company-cards">
            {PARTNER_TYPES.map((type) => (
              <article key={type.title} className="sgw-company-card">
                <h3>{type.title}</h3>
                <p>{type.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="blog-page-width sgw-company-section" aria-labelledby="partner-why">
          <h2 id="partner-why">Why partner with {SITE_NAME}</h2>
          <ul className="sgw-company-list">
            <li><strong>A clearer view of exposure.</strong> One platform that connects AI, infrastructure, software and cloud risk.</li>
            <li><strong>Built for the AI era.</strong> Help customers secure AI in the context of everything around it.</li>
            <li><strong>Flexible ways to work together.</strong> We shape the arrangement around how your business serves customers.</li>
          </ul>
        </section>

        <section className="blog-page-width sgw-company-section" aria-labelledby="partner-apply">
          <h2 id="partner-apply">Become a partner</h2>
          <div className="public-form-panel">
            <form className="demo-request-form" onSubmit={submit}>
              <label className="half-width">Full name<input name="fullName" autoComplete="name" required maxLength={255} /></label>
              <label className="half-width">Work email<input name="email" type="email" autoComplete="email" required maxLength={255} /></label>
              <label className="half-width">Organization<input name="organization" autoComplete="organization" required maxLength={255} /></label>
              <label className="half-width">Partner type
                <select name="partnerType" defaultValue="Security consultancies">
                  {PARTNER_TYPES.map((type) => <option key={type.title}>{type.title}</option>)}
                  <option>Other</option>
                </select>
              </label>
              <label className="full-width">Regions and markets<input name="regions" maxLength={255} /></label>
              <label className="full-width">How could we work together?<textarea name="message" rows={4} maxLength={2000} /></label>
              <div className="full-width">
                <button className="sgw-btn sgw-btn-red" type="submit">Apply to partner</button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </PublicDemoShell>
  );
}

export function ContactPage() {
  return (
    <PublicDemoShell>
      <div className="blog-index-page sgw-company-page">
        <PageHero eyebrow="Company" title="Get in touch">
          Questions about {SITE_NAME}, a demo or working together? Tell us a little and we&rsquo;ll get back to you.
        </PageHero>

        <section className="blog-page-width sgw-company-section sgw-contact-grid" aria-label="Contact details and form">
          <div>
            <h2>Talk to the team</h2>
            <dl className="sgw-contact-details">
              <div><dt>Email</dt><dd><a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a></dd></div>
              <div><dt>Location</dt><dd>Hyderabad, India</dd></div>
            </dl>
            <p>Want to see the platform? Request a demo using the form and we&rsquo;ll tailor it to your priorities.</p>
          </div>
          <div className="public-form-panel">
            <h2>Request for product demo</h2>
            <p className="panel-caption">We review requests before provisioning an isolated 7-day workspace with the full guided product experience.</p>
            <DemoRequestForm />
          </div>
        </section>
      </div>
    </PublicDemoShell>
  );
}
