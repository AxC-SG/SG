import React from 'react';
import { api } from '../api/client';
import { appendSearchToPath, pathForInventoryView } from '../app/routes';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolBadge } from '../components/EolBadge';
import { EolDetailDrawer } from '../components/EolDetailDrawer';
import type { SyncTriggerResponse } from '../features/connect/types';
import {
  useEolPackageAssetsQuery,
  useEolPackageStatusesQuery,
  useEolProductsQuery,
  useEolSummaryQuery
} from '../features/eol/queries';
import type { EolProductCatalog, PackageEolStatus } from '../features/eol/types';

const CATALOG_PAGE_SIZE = 25;
const PACKAGE_PAGE_SIZE = 25;
const ASSET_PAGE_SIZE = 25;

type EolTab = 'at-risk' | 'catalog';
type AtRiskFilter = 'all' | 'eol' | 'near-eol' | 'unknown';

// ---------------------------------------------------------------------------
// Catalog helpers
// ---------------------------------------------------------------------------

function matchesProduct(product: EolProductCatalog, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystacks = [
    product.slug,
    product.displayName,
    product.cpeVendor,
    product.cpeProduct,
    product.purlType,
    product.purlNamespace,
    ...(product.aliases ?? [])
  ];
  return haystacks.some(value => value?.toLowerCase().includes(needle));
}

function formatAliases(aliases?: string[]): string {
  if (!aliases || aliases.length === 0) return '-';
  if (aliases.length <= 3) return aliases.join(', ');
  return `${aliases.slice(0, 3).join(', ')} +${aliases.length - 3} more`;
}

function formatCount(value?: number): string {
  return (value ?? 0).toLocaleString();
}

function formatIdentifier(primary?: string, secondary?: string): string {
  if (!primary && !secondary) return '-';
  if (primary && secondary) return `${primary}/${secondary}`;
  return primary ?? secondary ?? '-';
}

function formatDate(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleDateString();
}

// ---------------------------------------------------------------------------
// At-Risk tab
// ---------------------------------------------------------------------------

type SelectedPackage = { packageName: string; ecosystem?: string };

const PACKAGE_COLUMNS: DataTableColumn[] = [
  { id: 'package', label: 'Package', header: 'Package', initialSize: 220 },
  { id: 'slug', label: 'EOL Slug', header: 'EOL Slug', initialSize: 160 },
  { id: 'cycle', label: 'Cycle', header: 'Cycle', initialSize: 110 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 140 },
  { id: 'eolDate', label: 'EOL Date', header: 'EOL Date', initialSize: 130 },
  { id: 'daysRemaining', label: 'Days Remaining', header: 'Days Remaining', initialSize: 130 },
  { id: 'assets', label: 'Affected Assets', header: 'Affected Assets', initialSize: 150 },
];

function buildPackageRows(
  packages: PackageEolStatus[],
  onSelectPackage: (pkg: SelectedPackage) => void
): DataTableRow[] {
  return packages.map((p) => ({
    id: `${p.packageName}::${p.ecosystem ?? ''}`,
    cells: {
      package: {
        content: (
          <>
            <div>{p.packageName || '-'}</div>
            {p.ecosystem && <span className="panel-caption mono">{p.ecosystem}</span>}
          </>
        )
      },
      slug: {
        content: p.eolSlug
          ? <span className="mono">{p.eolSlug}</span>
          : <span className="panel-caption">—</span>
      },
      cycle: {
        content: p.eolCycle
          ? <span className="mono">{p.eolCycle}</span>
          : <span className="panel-caption">—</span>
      },
      status: {
        content: (
          <EolBadge
            isEol={p.isEol}
            daysRemaining={p.eolDaysRemaining}
            eolDate={p.eolDate}
          />
        )
      },
      eolDate: { content: formatDate(p.eolDate) },
      daysRemaining: {
        content: p.eolDaysRemaining != null
          ? p.eolDaysRemaining.toLocaleString()
          : '-'
      },
      assets: {
        content: (
          <button
            type="button"
            className="eol-asset-count-btn"
            onClick={() => onSelectPackage({ packageName: p.packageName, ecosystem: p.ecosystem })}
          >
            {p.assetCount.toLocaleString()} {p.assetCount === 1 ? 'asset' : 'assets'}
          </button>
        )
      }
    }
  }));
}

// ---- Package asset drill-down panel ----------------------------------------

function PackageAssetPanel({ packageName, ecosystem, onClose }: {
  packageName: string;
  ecosystem?: string;
  onClose: () => void;
}) {
  const [page, setPage] = React.useState(0);
  const assetsQuery = useEolPackageAssetsQuery(
    { packageName, ecosystem, page, size: ASSET_PAGE_SIZE }
  );
  const assetPage = assetsQuery.data;
  const assets = assetPage?.content ?? [];
  const totalPages = assetPage?.totalPages ?? 1;
  const totalElements = assetPage?.totalElements ?? 0;

  return (
    <div className="eol-asset-panel">
      <div className="eol-asset-panel-header">
        <div>
          <strong className="eol-asset-panel-title">{packageName}</strong>
          {ecosystem && <span className="panel-caption mono"> · {ecosystem}</span>}
          <span className="panel-caption eol-asset-panel-count">
            {' '}— {totalElements.toLocaleString()} {totalElements === 1 ? 'asset' : 'assets'} affected
          </span>
        </div>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>

      {assetsQuery.isLoading ? (
        <div className="panel-caption" style={{ padding: '12px 0' }}>Loading assets...</div>
      ) : assetsQuery.error instanceof Error ? (
        <div className="notice error">{assetsQuery.error.message}</div>
      ) : assets.length === 0 ? (
        <div className="panel-caption">No assets found.</div>
      ) : (
        <div className="eol-asset-list">
          {assets.map((asset) => (
            <div key={asset.assetName} className="eol-asset-row">
              <span className="eol-asset-name">{asset.assetName}</span>
              {asset.versions && (
                <span className="panel-caption mono eol-asset-versions">{asset.versions}</span>
              )}
            </div>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="pagination-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page === 0}
            onClick={() => setPage(p => p - 1)}
          >
            Previous
          </button>
          <span className="panel-caption">Page {page + 1} of {totalPages}</span>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page >= totalPages - 1}
            onClick={() => setPage(p => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ---- At-Risk tab -----------------------------------------------------------

const FILTER_LABELS: Record<AtRiskFilter, string> = {
  all: 'All',
  eol: 'EOL',
  'near-eol': 'Near EOL',
  unknown: 'Unknown',
};

function AtRiskTab({ eolMappingReviewHref }: { eolMappingReviewHref: string }) {
  const [filter, setFilter] = React.useState<AtRiskFilter>('all');
  const [page, setPage] = React.useState(0);
  const [selectedPackage, setSelectedPackage] = React.useState<SelectedPackage | null>(null);

  const summaryQuery = useEolSummaryQuery();
  const summary = summaryQuery.data;

  const apiFilter = filter === 'all' ? undefined : filter;
  const packageQuery = useEolPackageStatusesQuery(
    { filter: apiFilter, page, size: PACKAGE_PAGE_SIZE }
  );
  const packagePage = packageQuery.data;
  const packages = React.useMemo(() => packagePage?.content ?? [], [packagePage?.content]);
  const totalPages = packagePage?.totalPages ?? 1;
  const totalElements = packagePage?.totalElements ?? 0;

  React.useEffect(() => {
    setPage(0);
    setSelectedPackage(null);
  }, [filter]);

  const rows = React.useMemo(
    () => buildPackageRows(packages, setSelectedPackage),
    [packages]
  );

  return (
    <>
      <div className="eol-risk-summary-strip">
        {([
          { key: 'eol', label: 'End of Life', value: summary?.eolCount, className: 'eol-risk-stat--danger' },
          { key: 'near-eol', label: 'Near EOL (≤90d)', value: summary?.nearEolCount, className: 'eol-risk-stat--warn' },
          { key: 'all', label: 'Supported', value: summary?.supportedCount, className: 'eol-risk-stat--ok' },
          { key: 'unknown', label: 'Unknown', value: summary?.unknownCount, className: 'eol-risk-stat--muted' },
        ] as const).map(({ key, label, value, className }) => (
          <button
            key={key}
            type="button"
            className={`eol-risk-stat ${className} ${filter === key ? 'active' : ''}`}
            onClick={() => setFilter(key === filter ? 'all' : key as AtRiskFilter)}
          >
            <strong className="eol-risk-stat-value">{(value ?? 0).toLocaleString()}</strong>
            <span className="eol-risk-stat-label">{label}</span>
          </button>
        ))}
      </div>

      <div className="toolbar eol-atrisk-toolbar">
        <div className="eol-filter-chips">
          {(Object.keys(FILTER_LABELS) as AtRiskFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              className={`chip ${filter === f ? 'chip-active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {FILTER_LABELS[f]}
            </button>
          ))}
        </div>
        <div className="button-row">
          <a href={eolMappingReviewHref} className="btn btn-secondary">
            Review Unmatched Mappings
          </a>
        </div>
      </div>

      {packageQuery.isLoading || packageQuery.isFetching ? (
        <div className="panel-caption" style={{ padding: '24px 0' }}>Loading...</div>
      ) : packageQuery.error instanceof Error ? (
        <div className="notice error">{packageQuery.error.message}</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">
          <p>{filter === 'all' ? 'No EOL data has been processed yet.' : `No packages match the "${FILTER_LABELS[filter]}" filter.`}</p>
        </div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="eol-at-risk-packages"
            columns={PACKAGE_COLUMNS}
            rows={rows}
          />
        </div>
      )}

      {selectedPackage && (
        <PackageAssetPanel
          packageName={selectedPackage.packageName}
          ecosystem={selectedPackage.ecosystem}
          onClose={() => setSelectedPackage(null)}
        />
      )}

      {totalPages > 1 && (
        <div className="pagination-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page === 0}
            onClick={() => setPage(p => p - 1)}
          >
            Previous
          </button>
          <span className="panel-caption">
            Page {page + 1} of {totalPages} · {totalElements.toLocaleString()} packages
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page >= totalPages - 1}
            onClick={() => setPage(p => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Product Catalog tab (unchanged logic, extracted)
// ---------------------------------------------------------------------------

function CatalogTab() {
  const productsQuery = useEolProductsQuery();
  const products = React.useMemo(() => productsQuery.data ?? [], [productsQuery.data]);
  const loading = productsQuery.isPending;
  const error = productsQuery.error instanceof Error ? productsQuery.error.message : null;
  const [query, setQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [drawer, setDrawer] = React.useState<EolProductCatalog | null>(null);

  React.useEffect(() => { setPage(0); }, [query]);

  const filteredProducts = React.useMemo(
    () => products.filter(product => matchesProduct(product, query)),
    [products, query]
  );

  const totalPages = Math.max(1, Math.ceil(filteredProducts.length / CATALOG_PAGE_SIZE));
  const activePage = Math.min(page, totalPages - 1);
  const pageItems = React.useMemo(
    () => filteredProducts.slice(activePage * CATALOG_PAGE_SIZE, activePage * CATALOG_PAGE_SIZE + CATALOG_PAGE_SIZE),
    [activePage, filteredProducts]
  );

  React.useEffect(() => {
    if (page !== activePage) setPage(activePage);
  }, [activePage, page]);

  const catalogStats = React.useMemo(() => ({
    products: products.length,
    lifecycleReady: products.filter(p => (p.releaseCount ?? 0) > 0).length,
    cpeMapped: products.filter(p => Boolean(p.cpeVendor || p.cpeProduct)).length,
    purlMapped: products.filter(p => Boolean(p.purlType || p.purlNamespace)).length,
    aliases: products.filter(p => (p.aliases?.length ?? 0) > 0).length
  }), [products]);

  const productColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'product', label: 'Product', header: 'Product', initialSize: 220 },
    { id: 'slug', label: 'Slug', header: 'Slug', initialSize: 150 },
    { id: 'coverage', label: 'Coverage', header: 'Coverage', initialSize: 190 },
    { id: 'referenceHints', label: 'Reference Hints', header: 'Reference Hints', initialSize: 260 },
    { id: 'aliases', label: 'Aliases', header: 'Aliases', initialSize: 240 },
    { id: 'actions', label: 'Actions', header: '', initialSize: 140 }
  ], []);

  const productRows = React.useMemo<DataTableRow[]>(() => (
    pageItems.map((product) => ({
      id: product.slug,
      cells: {
        product: {
          content: (
            <>
              <div>{product.displayName || product.slug}</div>
              {product.displayName && product.displayName !== product.slug && (
                <span className="panel-caption mono">{product.slug}</span>
              )}
            </>
          )
        },
        slug: { content: <span className="mono">{product.slug}</span> },
        coverage: {
          content: (
            <div className="eol-catalog-coverage">
              <strong
                className={
                  (product.releaseCount ?? 0) > 0
                    ? 'eol-catalog-coverage-title'
                    : 'eol-catalog-coverage-title eol-catalog-coverage-title--empty'
                }
              >
                {(product.releaseCount ?? 0) > 0
                  ? `${formatCount(product.releaseCount)} ${(product.releaseCount ?? 0) === 1 ? 'cycle' : 'cycles'} loaded`
                  : 'No release cycles'}
              </strong>
              <span className="panel-caption">
                {(product.releaseCount ?? 0) > 0 ? 'Lifecycle data ready' : 'Reference-only entry'}
              </span>
            </div>
          )
        },
        referenceHints: {
          content: (
            <div className="eol-catalog-reference-list">
              {(product.cpeVendor || product.cpeProduct) && (
                <div className="eol-catalog-reference-row">
                  <span className="eol-catalog-reference-label">CPE</span>
                  <span className="eol-catalog-reference-value mono">
                    {formatIdentifier(product.cpeVendor, product.cpeProduct)}
                  </span>
                </div>
              )}
              {(product.purlType || product.purlNamespace) && (
                <div className="eol-catalog-reference-row">
                  <span className="eol-catalog-reference-label">PURL</span>
                  <span className="eol-catalog-reference-value mono">
                    {formatIdentifier(product.purlType, product.purlNamespace)}
                  </span>
                </div>
              )}
              {!product.cpeVendor && !product.cpeProduct && !product.purlType && !product.purlNamespace && (
                <span className="panel-caption">No catalog identifiers</span>
              )}
            </div>
          )
        },
        aliases: {
          content: (
            <span className="eol-catalog-aliases">{formatAliases(product.aliases)}</span>
          )
        },
        actions: {
          content: (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setDrawer(product)}
            >
              View Details
            </button>
          )
        }
      }
    }))
  ), [pageItems]);

  function exportCsv() {
    const header = 'Display Name,Slug,Release Count,CPE Vendor,CPE Product,PURL Type,PURL Namespace,Aliases,Last Modified,Last Fetched At';
    const rows = filteredProducts.map(product =>
      [
        product.displayName ?? '',
        product.slug,
        product.releaseCount ?? 0,
        product.cpeVendor ?? '',
        product.cpeProduct ?? '',
        product.purlType ?? '',
        product.purlNamespace ?? '',
        (product.aliases ?? []).join('|'),
        product.lastModified ?? '',
        product.lastFetchedAt ?? ''
      ].map(value => `"${String(value).replace(/"/g, '""')}"`).join(',')
    );
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'eol-product-catalog.csv';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }

  return (
    <>
      <div className="ingestion-summary-grid">
        <div className="summary-card"><strong>Products</strong><span>{catalogStats.products.toLocaleString()}</span></div>
        <div className="summary-card"><strong>Lifecycle Ready</strong><span>{catalogStats.lifecycleReady.toLocaleString()}</span></div>
        <div className="summary-card"><strong>CPE Tagged</strong><span>{catalogStats.cpeMapped.toLocaleString()}</span></div>
        <div className="summary-card"><strong>PURL Tagged</strong><span>{catalogStats.purlMapped.toLocaleString()}</span></div>
        <div className="summary-card"><strong>Aliases</strong><span>{catalogStats.aliases.toLocaleString()}</span></div>
      </div>

      <div className="toolbar eol-catalog-toolbar">
        <label className="eol-catalog-search">
          <span className="panel-caption">Search catalog</span>
          <input
            type="text"
            className="filter-input"
            placeholder="slug, display name, alias, CPE, or PURL"
            value={query}
            onChange={event => setQuery(event.target.value)}
          />
        </label>
        <div className="button-row">
          <span className="panel-caption">{filteredProducts.length.toLocaleString()} matching products</span>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={exportCsv}
            disabled={filteredProducts.length === 0}
          >
            Export CSV
          </button>
        </div>
      </div>

      {error && (
        <div className="notice error" style={{ margin: '0 0 12px' }}>Error: {error}</div>
      )}

      {loading ? (
        <div className="panel-caption" style={{ padding: '24px 0' }}>Loading...</div>
      ) : (
        <>
          {pageItems.length === 0 ? (
            <div className="panel-caption" style={{ padding: '32px 0' }}>
              {query.trim().length > 0 ? 'No products matched your search.' : 'No EOL products have been ingested yet.'}
            </div>
          ) : (
            <div className="table-scroll">
              <DataTable
                storageKey="eol-product-catalog-v2"
                columns={productColumns}
                rows={productRows}
              />
            </div>
          )}

          {filteredProducts.length > CATALOG_PAGE_SIZE && (
            <div className="pagination-row">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={activePage === 0}
                onClick={() => setPage(current => current - 1)}
              >
                Previous
              </button>
              <span className="panel-caption">
                Page {activePage + 1} of {totalPages}
                {' · '}{filteredProducts.length.toLocaleString()} products
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={activePage >= totalPages - 1}
                onClick={() => setPage(current => current + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {drawer && (
        <EolDetailDrawer
          slug={drawer.slug}
          catalogProduct={drawer}
          packageName={drawer.displayName && drawer.displayName !== drawer.slug
            ? `${drawer.displayName} (${drawer.slug})`
            : drawer.slug}
          onClose={() => setDrawer(null)}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Data Freshness section
// ---------------------------------------------------------------------------

function DataFreshnessBar() {
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<SyncTriggerResponse | null>(null);

  async function handleRefresh() {
    setRunning(true);
    setResult(null);
    try {
      const response = await api.triggerEolFullRefresh();
      setResult(response);
    } catch {
      setResult({ runId: '', status: 'error', message: 'Failed to queue refresh. Check the Connect tab for details.' });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="eol-freshness-bar">
      <button
        type="button"
        className="btn btn-secondary"
        onClick={handleRefresh}
        disabled={running}
      >
        {running ? 'Queuing...' : 'Run Full Refresh'}
      </button>
      {result && (
        <span className={`panel-caption ${result.status === 'error' ? 'eol-freshness-error' : ''}`}>
          {result.status === 'error'
            ? result.message
            : `Queued — run #${result.runId}`}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

type EolPageProps = {
  embedded?: boolean;
  mode?: 'tenant' | 'platform';
};

export function EolPage({ embedded = false, mode = 'tenant' }: EolPageProps = {}) {
  const platformMode = mode === 'platform';
  const [activeTab, setActiveTab] = React.useState<EolTab>(platformMode ? 'catalog' : 'at-risk');
  const eolMappingReviewHref = appendSearchToPath(pathForInventoryView('overview'), {
    inventoryTabs: 'quality-eol',
    inventoryActiveTab: 'quality-eol',
    focus: 'eol-mapping-review'
  });

  const content = (
    <>
      <div className="panel-header">
        <div>
          <h3>End-of-Life</h3>
          <span className="panel-caption">
            {platformMode
              ? 'Platform-owned end-of-life catalog and lifecycle coverage'
              : 'Lifecycle risk across active inventory'}
          </span>
        </div>
        <DataFreshnessBar />
      </div>

      {!platformMode && (
        <div className="eol-page-tabs">
          <button
            type="button"
            className={`eol-page-tab ${activeTab === 'at-risk' ? 'active' : ''}`}
            onClick={() => setActiveTab('at-risk')}
          >
            At-Risk Components
          </button>
          <button
            type="button"
            className={`eol-page-tab ${activeTab === 'catalog' ? 'active' : ''}`}
            onClick={() => setActiveTab('catalog')}
          >
            Product Catalog
          </button>
        </div>
      )}

      {!platformMode && activeTab === 'at-risk' && <AtRiskTab eolMappingReviewHref={eolMappingReviewHref} />}
      {(platformMode || activeTab === 'catalog') && <CatalogTab />}
    </>
  );

  if (embedded) {
    return content;
  }

  return (
    <div className="page-grid">
      <section className="panel">
        {content}
      </section>
    </div>
  );
}
