import React from 'react';
import { Inbox, LockKeyhole, ShieldAlert } from 'lucide-react';
import { Alert, EmptyState } from './feedback';
import type { PreviewState } from '../previewContext';

export const SCENARIOS = [
  ['ready', 'Ready'], ['refreshing', 'Background refresh'], ['partial-error', 'Partial data failure'],
  ['save-error', 'Save failure'], ['empty', 'Empty workspace'], ['provisioning', 'Provisioning'],
  ['blocked', 'Access blocked'], ['expired', 'Demo expired'], ['session-error', 'Session verification failed'],
] as const;

export function ScenarioFrame({ state, onReset, children }: { state: PreviewState; onReset: () => void; children: React.ReactNode }) {
  const blocked: Partial<Record<PreviewState['scenario'], [string, string]>> = {
    provisioning: ['Workspace is provisioning', 'Workspace access becomes available after controlled provisioning and verification complete.'],
    blocked: ['Workspace access is blocked', 'Your data is retained. Contact your tenant administrator to restore access.'],
    expired: ['This demo has expired', 'Your data is retained. A platform owner can extend the demo expiry.'],
    'session-error': ['Unable to verify your session', 'Please try again. No workspace data is shown until the session is verified.'],
  };
  const blocking = blocked[state.scenario];
  if (blocking) return <div className="dp-page"><div className="dp-fixture-label">Sample {state.scenario} state</div><div className="dp-card dp-blocking-state"><EmptyState icon={<LockKeyhole size={24} />} title={blocking[0]} action={<button className="dp-btn" type="button" onClick={onReset}>Reset preview</button>}>{blocking[1]}</EmptyState></div></div>;
  if (state.scenario === 'empty') return <div className="dp-page"><div className="dp-fixture-label">Empty workspace fixture</div><div className="dp-card"><EmptyState icon={<Inbox size={24} />} title="No inventory has been discovered" action={<button className="dp-btn" type="button" onClick={onReset}>Reset preview</button>}>Connect a supported source to begin. No findings or trends are inferred from an empty inventory.</EmptyState></div></div>;
  return <>
    {state.scenario === 'refreshing' ? <div className="dp-scenario-banner" role="status">Refreshing supporting context… Current results remain visible.</div> : null}
    {state.scenario === 'partial-error' ? <div className="dp-scenario-banner"><Alert tone="warning" title="Some supporting data could not be loaded" action={<button className="dp-link" type="button" onClick={onReset}>Retry</button>}>Last available results are retained. Affected sections show their own unavailable state.</Alert></div> : null}
    {state.role === 'READ_ONLY_AUDITOR' && state.scope === 'tenant' ? <div className="dp-scenario-banner"><Alert title="Read-only access">You can inspect evidence and findings. Changes require a tenant administrator or security analyst.</Alert></div> : null}
    {!state.aiEntitled ? <div className="dp-scenario-banner"><Alert tone="warning" title="AI Security unavailable for this workspace">AI inventory and policy controls are unavailable in this entitlement fixture.</Alert></div> : null}
    {state.scenario === 'save-error' ? <div className="dp-scenario-banner dp-fixture-label"><ShieldAlert size={13} /> Save-failure fixture · Submit a change to inspect retained edits and retry feedback.</div> : null}
    {children}
  </>;
}
