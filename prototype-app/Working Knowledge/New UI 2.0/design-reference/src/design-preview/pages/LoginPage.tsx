import React from 'react';
import { Alert } from '../components/feedback';
import { PasswordInput, TextInput } from '../components/forms';

// Reference for public/auth pages (DemoPublicPages LoginPage, SetupSessionPage, invite pages).
// Copy, field labels, button labels and disabled rules match LoginPage today.

export function LoginPage({ onSignIn }: { onSignIn: () => void }) {
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [pending, setPending] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (password === 'wrong') { setError('Invalid email or password.'); return; }
    setPending(true);
    window.setTimeout(onSignIn, 600);
  };

  return (
    <div className="dp-auth">
      <div className="dp-auth-brand">
        <span className="dp-brand-mark">S</span>
        <span className="dp-brand-name">ScoutGrid</span>
      </div>
      <section className="dp-auth-card">
        <h1>Log in to ScoutGrid</h1>
        <p>Use your email and password to access your tenant workspace or the platform console.</p>
        <Alert tone="success" role="status">Password created successfully. Sign in with your email and new password to continue.</Alert>
        <form className="dp-form" onSubmit={submit}>
          <label className="dp-field">
            <span className="dp-label">Email</span>
            <TextInput type="text" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
          </label>
          <label className="dp-field">
            <span className="dp-label">Password</span>
            <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </label>
          <button className="dp-btn dp-btn--primary dp-btn--block" type="submit" disabled={pending || !email.trim() || !password.trim()}>
            {pending ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
        {error ? <Alert tone="danger" role="alert">{error}</Alert> : null}
        <div className="dp-auth-personas">
          <h2>Non-production test personas</h2>
          <div className="dp-row-gap">
            {['Tenant Admin', 'Security Analyst', 'Platform Owner'].map((p) => <button key={p} type="button" className="dp-btn dp-btn--sm">{p}</button>)}
          </div>
        </div>
      </section>
    </div>
  );
}
