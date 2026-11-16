import React from 'react';
import { useActor } from '../auth/context';
import { AssignOccurrenceOwnerDialog } from './AssignOccurrenceOwnerDialog';
import type { OccurrenceKind } from './occurrenceTypes';
import { canManualAssign } from './permissions';

/** "Assign owner" for one occurrence row; hidden unless the actor may MANUAL_ASSIGN and the row is eligible. */
export function AssignOwnerButton({ kind, rowId, rowLabel, eligible = true }: { kind: OccurrenceKind; rowId: string; rowLabel: string; eligible?: boolean }) {
  const actor = useActor();
  const [open, setOpen] = React.useState(false);
  const [done, setDone] = React.useState(false);
  if (!eligible || !canManualAssign(actor)) return null;
  return (
    <>
      <button type="button" className="btn btn-ghost btn-sm" aria-label={`Assign owner for ${rowLabel}`} onClick={() => { setDone(false); setOpen(true); }}>
        Assign owner
      </button>
      {done && <span className="panel-caption" role="status">Owner assigned.</span>}
      <AssignOccurrenceOwnerDialog kind={kind} rowId={rowId} rowLabel={rowLabel} isOpen={open} onClose={() => setOpen(false)} onAssigned={() => setDone(true)} />
    </>
  );
}
