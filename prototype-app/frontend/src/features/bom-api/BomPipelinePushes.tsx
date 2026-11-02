import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type BomInventoryItem } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { DataTable, type DataTableColumn, type DataTableRow } from '../../components/DataTable';
import { formatTimestamp } from '../../lib/time';

const COLUMNS: DataTableColumn[] = [
  { id: 'time', label: 'Pushed', header: 'Pushed', initialSize: 180, priority: 'essential' },
  { id: 'type', label: 'BOM', header: 'BOM', initialSize: 100 },
  { id: 'pipeline', label: 'Pipeline', header: 'Pipeline', initialSize: 150 },
  { id: 'build', label: 'Build', header: 'Build', initialSize: 120 },
  { id: 'correlator', label: 'Correlator', header: 'Correlator', initialSize: 200 },
  { id: 'format', label: 'Format', header: 'Format', initialSize: 140 },
  { id: 'components', label: 'Components', header: 'Components', initialSize: 120 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 120 },
];

function build(label?: string | null): string {
  return label?.startsWith('build:') ? label.slice('build:'.length) : '—';
}

function isPipelinePush(item: BomInventoryItem): boolean {
  return item.sourceType === 'API';
}

export function BomPipelinePushes() {
  const query = useQuery({ queryKey: ['bom-pipeline-pushes'], queryFn: () => api.listBomInventory(0, 200) });

  const pushes = React.useMemo(() => (query.data ?? []).filter(isPipelinePush), [query.data]);
  const rows = React.useMemo<DataTableRow[]>(() => pushes.map((item) => ({
    id: item.id,
    cells: {
      time: { content: formatTimestamp(item.ingestedAt) },
      type: { content: item.bomType },
      pipeline: { content: item.sourceSystem || '—' },
      build: { content: build(item.sourceLabel) },
      correlator: { content: item.sourceReference || '—' },
      format: { content: `${item.format} ${item.formatVersion ?? ''} ${item.documentFormat ?? ''}`.trim() },
      components: { content: item.componentCount.toLocaleString() },
      status: { content: item.status },
    },
  })), [pushes]);

  const state = query.isPending ? 'pending' : query.isError ? 'error' : rows.length === 0 ? 'empty' : 'ready';

  return (
    <div className="form-section">
      <p className="form-section-title">Recent pipeline pushes</p>
      <AsyncSection
        state={state}
        loadingLabel="Loading pipeline pushes…"
        emptyMessage="No BOMs have been pushed from a pipeline yet."
        errorMessage="Pipeline pushes could not be loaded."
        onRetry={() => void query.refetch()}
        retryLabel="Retry pipeline pushes"
        retrying={query.isFetching}
      >
        <div className="table-scroll">
          <DataTable storageKey="bom-pipeline-pushes-table" label="Recent pipeline pushes" columns={COLUMNS} rows={rows} />
        </div>
      </AsyncSection>
    </div>
  );
}
