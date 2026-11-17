import type { CampaignNotifyGroupRequest } from './types';

/** A recipient chosen in the launch wizard: a team by ID (its channel is used) or a custom address. */
export type NotifyDraft =
  | { recipientType: 'TEAM'; teamId: string; teamName: string }
  | { recipientType: 'CUSTOM'; groupName: string; groupEmail: string };

export function notifyDraftKey(draft: NotifyDraft): string {
  return draft.recipientType === 'TEAM' ? `team:${draft.teamId}` : `custom:${draft.groupEmail.toLowerCase()}`;
}

/** Request rows for the chosen recipients. TEAM rows never carry an address; CUSTOM rows are never owner recipients. */
export function notifyDraftsToRequest(drafts: NotifyDraft[]): CampaignNotifyGroupRequest[] {
  return drafts.map((draft) => draft.recipientType === 'TEAM'
    ? { recipientType: 'TEAM', teamId: draft.teamId, groupName: draft.teamName, roleLabel: 'Owner team', triggerSummary: 'Status changes, notes, closure risk', notificationsPaused: false }
    : { recipientType: 'CUSTOM', groupName: draft.groupName, groupEmail: draft.groupEmail, roleLabel: 'Custom recipient', triggerSummary: 'Status changes, notes, closure risk', notificationsPaused: false });
}
