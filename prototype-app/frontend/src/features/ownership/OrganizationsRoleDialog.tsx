import React from 'react';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { useAwsOrganizationsRoleQuery, useSaveAwsOrganizationsRoleMutation, useTestAwsOrganizationsRoleMutation } from './queries';

type Props = { isOpen: boolean; onClose: () => void; onSaved: (message: string) => void };

/**
 * The optional AWS Organizations role for account tags (Phase 0B §2.2.1). The role sits in the management or a
 * delegated-admin account and grants only organizations:ListTagsForResource and organizations:DescribeAccount. The
 * external ID is write-only: it is never shown, and a new role ARN needs it again. Clearing the ARN removes the role.
 */
export function OrganizationsRoleDialog({ isOpen, onClose, onSaved }: Props) {
  const role = useAwsOrganizationsRoleQuery(isOpen);
  const save = useSaveAwsOrganizationsRoleMutation();
  const test = useTestAwsOrganizationsRoleMutation();
  const arnRef = React.useRef<HTMLInputElement>(null);
  const [roleArn, setRoleArn] = React.useState('');
  const [externalId, setExternalId] = React.useState('');
  const [accountId, setAccountId] = React.useState('');

  // Fill the ARN once per opening, so a late response never overwrites what the admin typed.
  const filled = React.useRef(false);
  React.useEffect(() => {
    if (!isOpen) filled.current = false;
    else if (role.data && !filled.current) {
      filled.current = true;
      setRoleArn((typed) => (typed === '' ? role.data?.roleArn ?? '' : typed));
    }
  }, [isOpen, role.data]);

  const close = () => {
    setExternalId('');
    setRoleArn('');
    save.reset();
    test.reset();
    onClose();
  };
  const changingRole = roleArn.trim() !== (role.data?.roleArn ?? '');
  const valid = roleArn.trim() === '' || !changingRole || externalId.trim() !== '';

  return (
    <OwnershipFormDialog
      isOpen={isOpen}
      title="AWS account tags"
      description="Account owner and team tags are read through a separate role in your management or delegated-admin account. It needs only organizations:ListTagsForResource and organizations:DescribeAccount and is never used for discovery."
      submitLabel={roleArn.trim() === '' ? 'Remove role' : 'Save role'}
      busy={save.isPending}
      busyMessage="Saving the role…"
      error={save.isError ? ownershipErrorText(save.error, 'The role could not be saved.') : null}
      submitDisabled={!valid}
      onSubmit={() => save.mutate(
        { roleArn: roleArn.trim(), externalId: externalId.trim() === '' ? null : externalId.trim() },
        { onSuccess: (saved) => { setExternalId(''); onSaved(saved.configured ? 'Organizations role saved.' : 'Organizations role removed.'); } }
      )}
      onClose={close}
      initialFocusRef={arnRef}
    >
      <label>
        <span>Role ARN</span>
        <input ref={arnRef} placeholder="arn:aws:iam::123456789012:role/OwnershipTags" value={roleArn}
          onChange={(event) => setRoleArn(event.target.value)} />
      </label>
      <label>
        <span>External ID{role.data?.externalIdSet && !changingRole ? ' (leave blank to keep)' : ''}</span>
        <input type="password" autoComplete="new-password" value={externalId} onChange={(event) => setExternalId(event.target.value)} />
      </label>
      {role.data?.configured && (
        <fieldset>
          <legend>Connection test</legend>
          <label>
            <span>Account to describe (optional, 12 digits)</span>
            <input inputMode="numeric" value={accountId} onChange={(event) => setAccountId(event.target.value)} />
          </label>
          <button type="button" className="btn btn-ghost btn-sm" disabled={test.isPending}
            onClick={() => test.mutate(accountId.trim() === '' ? undefined : accountId.trim())}>
            {test.isPending ? 'Testing…' : 'Test the saved role'}
          </button>
          {test.data && (
            <div className={`notice ${test.data.succeeded ? 'success' : 'error'}`} role="status">
              {test.data.message}{test.data.accountName ? ` (${test.data.accountName})` : ''}
            </div>
          )}
          {test.isError && <div className="notice error" role="alert">{ownershipErrorText(test.error, 'The role could not be tested.')}</div>}
        </fieldset>
      )}
    </OwnershipFormDialog>
  );
}
