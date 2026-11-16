import React from 'react';
import type { OwnershipTeam } from '../ownership/types';
import { notifyDraftKey, type NotifyDraft } from './notifyDrafts';

/**
 * Notify recipients for the launch wizard (Phase 0B §4.6). Teams come from the canonical team list; a team with no
 * notification channel is flagged. Custom recipients are offered only to roles the server accepts for them.
 */
export function CampaignRecipientsPicker({ teams, teamsLoading, teamsError, value, onChange, canAddCustom, teamsWithoutChannel }: {
  teams: OwnershipTeam[]; teamsLoading: boolean; teamsError: boolean; value: NotifyDraft[]; onChange: (next: NotifyDraft[]) => void;
  canAddCustom: boolean; teamsWithoutChannel: Set<string>;
}) {
  const [label, setLabel] = React.useState('');
  const [email, setEmail] = React.useState('');
  const selectedKeys = new Set(value.map(notifyDraftKey));
  const toggleTeam = (team: OwnershipTeam) => {
    const draft: NotifyDraft = { recipientType: 'TEAM', teamId: team.id, teamName: team.name };
    const key = notifyDraftKey(draft);
    onChange(selectedKeys.has(key) ? value.filter((item) => notifyDraftKey(item) !== key) : [...value, draft]);
  };
  const addCustom = () => {
    const draft: NotifyDraft = { recipientType: 'CUSTOM', groupName: label.trim(), groupEmail: email.trim() };
    if (!draft.groupName || !draft.groupEmail || selectedKeys.has(notifyDraftKey(draft))) return;
    onChange([...value, draft]);
    setLabel(''); setEmail('');
  };

  return (
    <div className="campaign-recipients">
      <h4>Notify teams</h4>
      {teamsLoading && <p className="muted" role="status">Loading teams…</p>}
      {teamsError && <div className="notice error" role="alert">Teams could not be loaded.</div>}
      {!teamsLoading && !teamsError && teams.length === 0 && <p className="panel-caption">No active teams yet. Create teams under Configurations, Ownership.</p>}
      <div className="campaign-chip-grid">
        {teams.map((team) => (
          <button
            key={team.id}
            type="button"
            className={selectedKeys.has(`team:${team.id}`) ? 'campaign-chip active' : 'campaign-chip'}
            aria-pressed={selectedKeys.has(`team:${team.id}`)}
            onClick={() => toggleTeam(team)}
          >
            {team.name}
          </button>
        ))}
      </div>
      {value.filter((item) => item.recipientType === 'TEAM' && (teamsWithoutChannel.has(item.teamId)
        || teams.find((team) => team.id === item.teamId)?.notificationChannel === false)).map((item) => (
        <div key={notifyDraftKey(item)} className="notice warning" role="status">
          {item.recipientType === 'TEAM' ? item.teamName : ''} has no notification channel; its launch notification will be recorded as skipped.
        </div>
      ))}
      {canAddCustom && (
        <fieldset className="campaign-custom-recipient">
          <legend>Custom recipient (not an owner recipient)</legend>
          <label><span>Recipient label</span><input value={label} onChange={(event) => setLabel(event.target.value)} /></label>
          <label><span>Recipient email</span><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
          <button type="button" className="btn btn-secondary btn-sm" disabled={!label.trim() || !email.trim()} onClick={addCustom}>Add custom recipient</button>
        </fieldset>
      )}
      {value.filter((item) => item.recipientType === 'CUSTOM').map((item) => (
        <div key={notifyDraftKey(item)} className="panel-caption">
          {item.groupName} · {item.groupEmail} · not an owner recipient{' '}
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => onChange(value.filter((other) => other !== item))}>Remove {item.groupName}</button>
        </div>
      ))}
    </div>
  );
}

/** Wizard options that change who a campaign covers and who coordinates it. */
export function CampaignLaunchOptions({ teams, coordinatingTeamId, includeExcepted, onCoordinatingTeam, onIncludeExcepted }: {
  teams: OwnershipTeam[]; coordinatingTeamId: string; includeExcepted: boolean;
  onCoordinatingTeam: (id: string) => void; onIncludeExcepted: (value: boolean) => void;
}) {
  return (
    <div className="campaign-launch-options">
      <label>
        <span>Coordinating team (optional)</span>
        <select value={coordinatingTeamId} onChange={(event) => onCoordinatingTeam(event.target.value)}>
          <option value="">None</option>
          {teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
        </select>
      </label>
      <p className="panel-caption">A coordinating team follows the campaign. It does not own any finding or change who does.</p>
      <label>
        <input type="checkbox" checked={includeExcepted} onChange={(event) => onIncludeExcepted(event.target.checked)} />
        <span>Include suppressed, accepted-risk and false-positive findings</span>
      </label>
    </div>
  );
}
