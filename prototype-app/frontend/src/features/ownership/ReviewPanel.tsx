import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { SegmentedControl } from '../../components/SegmentedControl';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { useCloseReviewItemMutation, useOwnershipReviewQuery } from './queries';
import type { OwnershipReviewItem, OwnershipReviewType } from './types';

type ReviewState = 'OPEN' | 'RESOLVED' | 'DISMISSED';

const REVIEW_TYPE_LABELS: Record<OwnershipReviewType, { label: string; guidance: string }> = {
  UNMAPPED_VALUE: { label: 'Unmapped value', guidance: 'A source named a team value with no matching team or alias. Add an alias on the right team.' },
  AMBIGUOUS_IDENTITY: { label: 'Ambiguous identity', guidance: 'Two directory records share an identifier. Records are never merged automatically.' },
  CONFLICT: { label: 'Conflict', guidance: 'Sources at the same priority name different teams. Fix the source or assign the owner manually.' },
  INACTIVE_OWNER: { label: 'Inactive owner', guidance: 'A claim names an archived team. Restore the team or correct the source.' },
  INHERITANCE_ERROR: { label: 'Inheritance error', guidance: 'The ownership parent chain has a cycle, a missing parent or too many levels.' },
  PRODUCER_ANOMALY: { label: 'Producer anomaly', guidance: 'A source run would have changed too much ownership at once and was paused before publishing.' }
};

const COLUMNS: DataTableColumn[] = [
  { id: 'type', label: 'Type', header: 'Type', priority: 'essential', initialSize: 170, minWidth: 140 },
  { id: 'details', label: 'Details', header: 'Details', priority: 'essential', initialSize: 320, minWidth: 200 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 120 },
  { id: 'count', label: 'Occurrences', header: 'Occurrences', initialSize: 110 },
  { id: 'lastSeen', label: 'Last seen', header: 'Last seen', initialSize: 170 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 180 }
];

/** Details hold stable IDs and counts only (never names or unresolved personal values); show them as key/value text. */
function describeDetails(details: string | null): string {
  if (!details) return '';
  try {
    const parsed = JSON.parse(details) as Record<string, unknown>;
    return Object.entries(parsed).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : String(value)}`).join(' · ');
  } catch {
    return details;
  }
}

function formatTime(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function ReviewPanel({ canResolve }: { canResolve: boolean }) {
  const [state, setState] = React.useState<ReviewState>('OPEN');
  const [type, setType] = React.useState('');
  const items = useOwnershipReviewQuery(state, type);
  const close = useCloseReviewItemMutation();
  const [target, setTarget] = React.useState<{ item: OwnershipReviewItem; to: 'RESOLVED' | 'DISMISSED' } | null>(null);
  const [note, setNote] = React.useState('');
  const [message, setMessage] = React.useState('');

  const rows = (items.data ?? []).map((item) => ({
    id: item.id,
    cells: {
      type: { content: <span title={REVIEW_TYPE_LABELS[item.itemType]?.guidance}>{REVIEW_TYPE_LABELS[item.itemType]?.label ?? item.itemType}</span> },
      details: { content: <span className="mono ownership-wrap">{describeDetails(item.details)}</span> },
      source: { content: item.sourceKind ?? '—' },
      count: { content: item.occurrenceCount.toLocaleString() },
      lastSeen: { content: formatTime(item.lastSeenAt) },
      actions: {
        content: item.state === 'OPEN' && canResolve ? (
          <div className="button-row">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => { close.reset(); setNote(''); setTarget({ item, to: 'RESOLVED' }); }}>Resolve</button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => { close.reset(); setNote(''); setTarget({ item, to: 'DISMISSED' }); }}>Dismiss</button>
          </div>
        ) : item.state !== 'OPEN' ? <span className="panel-caption">{item.state === 'RESOLVED' ? 'Resolved' : 'Dismissed'} {formatTime(item.resolvedAt)}</span> : null
      }
    }
  }));

  const filtered = type !== '';
  const sectionState = items.isPending ? 'pending' : items.isError && !items.data ? 'error'
    : rows.length > 0 ? 'ready' : filtered ? 'filtered-empty' : 'empty';

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <SegmentedControl<ReviewState>
          ariaLabel="Review item state"
          value={state}
          onChange={setState}
          options={[{ value: 'OPEN', label: 'Open' }, { value: 'RESOLVED', label: 'Resolved' }, { value: 'DISMISSED', label: 'Dismissed' }]}
        />
        <label className="ownership-search">
          <span>Type</span>
          <select value={type} onChange={(event) => setType(event.target.value)}>
            <option value="">All types</option>
            {Object.entries(REVIEW_TYPE_LABELS).map(([value, { label }]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={sectionState}
        loadingLabel="Loading review items…"
        errorMessage={ownershipErrorText(items.error, 'Review items could not be loaded.')}
        onRetry={() => void items.refetch()}
        retrying={items.isFetching}
        emptyTitle={state === 'OPEN' ? 'Nothing to review' : 'No closed items'}
        emptyMessage={state === 'OPEN' ? 'Ownership sources have not raised anything that needs a decision.' : 'No review items have been closed in this state.'}
        filteredEmptyMessage="No review items of this type."
        onClearFilters={() => setType('')}
        refreshError={items.isError && items.data ? 'The latest review items could not be loaded; showing the previous result.' : undefined}
        isRefreshing={items.isFetching && !items.isPending}
      >
        <DataTable storageKey="ownership-review" columns={COLUMNS} rows={rows} label="Review items" />
      </AsyncSection>

      <OwnershipFormDialog
        isOpen={target !== null}
        title={target?.to === 'RESOLVED' ? 'Resolve review item' : 'Dismiss review item'}
        description={target ? REVIEW_TYPE_LABELS[target.item.itemType]?.guidance : undefined}
        submitLabel={target?.to === 'RESOLVED' ? 'Mark resolved' : 'Dismiss'}
        busy={close.isPending}
        busyMessage="Closing the review item…"
        error={close.isError ? ownershipErrorText(close.error, 'The review item could not be closed.') : null}
        onSubmit={() => target && close.mutate({ itemId: target.item.id, state: target.to, note: note.trim() || undefined }, {
          onSuccess: () => { setTarget(null); setMessage(target.to === 'RESOLVED' ? 'Review item resolved.' : 'Review item dismissed.'); }
        })}
        onClose={() => setTarget(null)}
      >
        <label>
          <span>Note (optional)</span>
          <textarea rows={3} maxLength={1000} value={note} onChange={(event) => setNote(event.target.value)} />
        </label>
      </OwnershipFormDialog>
    </div>
  );
}
