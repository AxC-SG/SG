import React from 'react';
import { SegmentedControl } from '../../components/SegmentedControl';
import { CbomAssetsPanel } from '../inventory/CbomAssetsPanel';
import { CbomDiffPanel } from './CbomDiffPanel';
import { CbomInventoryPanel } from './CbomInventoryPanel';
import { CbomReportsPanel } from './CbomReportsPanel';

type View = 'assets' | 'evidence' | 'changes' | 'reports';

/** CBOM document detail: assets, filterable evidence, semantic changes and persisted reports. */
export function CbomDocumentPanel({ bomId }: { bomId: string }) {
  const [view, setView] = React.useState<View>('assets');
  return (
    <div className="cbom-document-panel">
      <SegmentedControl<View>
        ariaLabel="CBOM document view"
        value={view}
        onChange={setView}
        options={[
          { value: 'assets', label: 'Assets' },
          { value: 'evidence', label: 'Evidence' },
          { value: 'changes', label: 'Changes' },
          { value: 'reports', label: 'Reports' },
        ]}
      />
      {view === 'assets' && <CbomAssetsPanel bomId={bomId} />}
      {view === 'evidence' && <CbomInventoryPanel initialFilters={{ bomId }} />}
      {view === 'changes' && <CbomDiffPanel bomId={bomId} />}
      {view === 'reports' && <CbomReportsPanel bomId={bomId} />}
    </div>
  );
}
