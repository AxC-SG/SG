import React from 'react';
import { FilterBuilder, FilterBuilderField } from '../../components/FilterBuilder';
import { FilterValueOption, FilterValueSelectCard } from '../../components/FilterValueSelectCard';
import { INVENTORY_FILTER_CATEGORIES } from './config';
import { normalizeHostReviewCategory } from './helpers';
import type {
  HostReviewCategory,
  InventoryComponentFilterKey,
  InventoryScopedAssetType,
  InventoryViewKey
} from './types';

type ComponentFilterState = {
  activeFilters: InventoryComponentFilterKey[];
  assetTypes: string[];
  statuses: string[];
  sourceSystems: string[];
  ecosystems: string[];
  reviewCategories: HostReviewCategory[];
  query: string;
  assetTypeOptions: FilterValueOption[];
  componentStatusOptions: FilterValueOption[];
  sourceSystemOptions: FilterValueOption[];
  ecosystemOptions: FilterValueOption[];
  hostReviewOptions: FilterValueOption[];
  addFilter: (key: InventoryComponentFilterKey) => void;
  removeFilter: (key: InventoryComponentFilterKey) => void;
  clearFilters: () => void;
  setAssetTypes: (values: string[]) => void;
  setStatuses: (values: string[]) => void;
  setSourceSystems: (values: string[]) => void;
  setEcosystems: (values: string[]) => void;
  setReviewCategories: (values: HostReviewCategory[]) => void;
  setQuery: (value: string) => void;
  setPage: (page: number) => void;
};

type Props = {
  selectedView: InventoryViewKey;
  scopedAssetType: InventoryScopedAssetType;
  inventoryFilterFields: FilterBuilderField[];
  loading: boolean;
  refreshInventory: () => void;
  componentFilters: ComponentFilterState;
};

function componentFilterChipLabel(
  key: InventoryComponentFilterKey,
  filters: ComponentFilterState
): string {
  if (key === 'assetType') {
    return `Asset Type${filters.assetTypes.length > 0 ? ` (${filters.assetTypes.length})` : ''}`;
  }
  if (key === 'componentStatus') {
    return `Component Status${filters.statuses.length > 0 ? ` (${filters.statuses.length})` : ''}`;
  }
  if (key === 'sourceSystem') {
    return `Source System${filters.sourceSystems.length > 0 ? ` (${filters.sourceSystems.length})` : ''}`;
  }
  if (key === 'ecosystem') {
    return `Ecosystem${filters.ecosystems.length > 0 ? ` (${filters.ecosystems.length})` : ''}`;
  }
  if (key === 'reviewCategory') {
    return `Host Review${filters.reviewCategories.length > 0 ? ` (${filters.reviewCategories.length})` : ''}`;
  }
  return `Inventory Search${filters.query.trim() ? ' (1)' : ''}`;
}

export function InventoryFiltersPanel({
  selectedView,
  scopedAssetType,
  inventoryFilterFields,
  loading,
  refreshInventory,
  componentFilters
}: Props) {
  return (
    <section className="panel">
      <div>
        {selectedView === 'sbom' && (
          <div className="panel-caption">
            Repository inventory is scoped to application assets. GHCR image SBOMs appear only in <span className="mono">Inventory &gt; Container Images</span>.
          </div>
        )}
        {selectedView === 'hosts' && (
          <div className="panel-caption">
            Host inventory is persisted as normalized software components across host assets. When a source already provides trustworthy normalized
            inventory, it is retained; otherwise deterministic normalization is applied before the software appears here.
          </div>
        )}
        <div className="findings-filter-shell">
          <div className="findings-filter-builder-row">
            <FilterBuilder
              categories={INVENTORY_FILTER_CATEGORIES}
              fields={inventoryFilterFields}
              activeKeys={componentFilters.activeFilters}
              onAddFilter={(key) => componentFilters.addFilter(key as InventoryComponentFilterKey)}
            />
            <div className="findings-filter-active-chips">
              {componentFilters.activeFilters.map((key) => (
                <button
                  key={key}
                  type="button"
                  className="findings-filter-chip-tag"
                  onClick={() => componentFilters.removeFilter(key)}
                  title="Remove filter"
                >
                  <span>{componentFilterChipLabel(key, componentFilters)}</span>
                  <span aria-hidden="true">x</span>
                </button>
              ))}
            </div>
          </div>

          <div className="findings-active-filter-grid">
            {scopedAssetType === 'ALL' && componentFilters.activeFilters.includes('assetType') && (
              <FilterValueSelectCard
                label="Asset Type"
                selectedValues={componentFilters.assetTypes}
                options={componentFilters.assetTypeOptions}
                onChange={(values) => {
                  componentFilters.setAssetTypes(values);
                  componentFilters.setPage(0);
                }}
                onRemove={() => componentFilters.removeFilter('assetType')}
              />
            )}

            {componentFilters.activeFilters.includes('componentStatus') && (
              <FilterValueSelectCard
                label="Component Status"
                selectedValues={componentFilters.statuses}
                options={componentFilters.componentStatusOptions}
                onChange={(values) => {
                  componentFilters.setStatuses(values);
                  componentFilters.setPage(0);
                }}
                onRemove={() => componentFilters.removeFilter('componentStatus')}
              />
            )}

            {componentFilters.activeFilters.includes('sourceSystem') && (
              <FilterValueSelectCard
                label="Source System"
                selectedValues={componentFilters.sourceSystems}
                options={componentFilters.sourceSystemOptions}
                onChange={(values) => {
                  componentFilters.setSourceSystems(values);
                  componentFilters.setPage(0);
                }}
                onRemove={() => componentFilters.removeFilter('sourceSystem')}
              />
            )}

            {componentFilters.activeFilters.includes('ecosystem') && (
              <FilterValueSelectCard
                label="Ecosystem"
                selectedValues={componentFilters.ecosystems}
                options={componentFilters.ecosystemOptions}
                onChange={(values) => {
                  componentFilters.setEcosystems(values);
                  componentFilters.setPage(0);
                }}
                onRemove={() => componentFilters.removeFilter('ecosystem')}
              />
            )}

            {selectedView === 'hosts' && componentFilters.activeFilters.includes('reviewCategory') && (
              <FilterValueSelectCard
                label="Host Review"
                selectedValues={componentFilters.reviewCategories}
                options={componentFilters.hostReviewOptions}
                onChange={(values) => {
                  componentFilters.setReviewCategories(values
                    .map(normalizeHostReviewCategory)
                    .filter((value): value is HostReviewCategory => value !== null));
                  componentFilters.setPage(0);
                }}
                onRemove={() => componentFilters.removeFilter('reviewCategory')}
              />
            )}

            {componentFilters.activeFilters.includes('query') && (
              <label className="findings-filter-chip findings-filter-text-card">Inventory Search
                <button
                  type="button"
                  className="findings-filter-chip-remove"
                  onClick={() => componentFilters.removeFilter('query')}
                  aria-label="Remove Inventory Search filter"
                >
                  x
                </button>
                <input
                  value={componentFilters.query}
                  onChange={(event) => {
                    componentFilters.setQuery(event.target.value);
                    componentFilters.setPage(0);
                  }}
                  placeholder="asset, package, software identity, or purl"
                  className="mono"
                />
              </label>
            )}
          </div>

          <div className="findings-filter-row">
            <div className="findings-filter-actions">
              <button className="btn btn-secondary btn-inline" type="button" onClick={componentFilters.clearFilters}>
                Clear Filters
              </button>
              <button className="btn btn-secondary btn-inline" type="button" onClick={refreshInventory} disabled={loading}>
                {loading ? 'Refreshing...' : 'Refresh Inventory'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
