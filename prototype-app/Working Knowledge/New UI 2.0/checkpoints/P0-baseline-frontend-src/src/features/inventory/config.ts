import type {
  InventoryComponentFilterValues
} from './api-types';
import type { FilterBuilderCategory, FilterBuilderField } from '../../components/FilterBuilder';

export const DEFAULT_COMPONENT_FILTERS: InventoryComponentFilterValues = {
  assetTypes: ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'],
  componentStatuses: ['ACTIVE', 'RETIRED'],
  sourceSystems: ['api', 'github', 'servicenow'],
  ecosystems: []
};

export const INVENTORY_FILTER_CATEGORIES: FilterBuilderCategory[] = [
  { key: 'inventory', label: 'Inventory' },
  { key: 'ingestion', label: 'Ingestion' },
  { key: 'review', label: 'Review' }
];

export const INVENTORY_FILTER_FIELDS: FilterBuilderField[] = [
  {
    key: 'assetType',
    label: 'Asset Type',
    categoryKey: 'inventory',
    description: 'Filter inventory records by the underlying asset class.',
    typeLabel: 'Enum property'
  },
  {
    key: 'componentStatus',
    label: 'Component Status',
    categoryKey: 'inventory',
    description: 'Filter inventory rows by whether the component is active or retired.',
    typeLabel: 'Enum property'
  },
  {
    key: 'ecosystem',
    label: 'Ecosystem',
    categoryKey: 'inventory',
    description: 'Filter by package ecosystem such as Maven, npm, or PyPI.',
    typeLabel: 'Enum property'
  },
  {
    key: 'sourceSystem',
    label: 'Source System',
    categoryKey: 'ingestion',
    description: 'Filter records by how the inventory was ingested.',
    typeLabel: 'Enum property'
  },
  {
    key: 'reviewCategory',
    label: 'Host Review',
    categoryKey: 'review',
    description: 'Filter host inventory rows by deterministic review blockers such as missing version, unmapped software, or low-confidence host alias resolution.',
    typeLabel: 'Enum property'
  },
  {
    key: 'query',
    label: 'Inventory Search',
    categoryKey: 'inventory',
    description: 'Search asset name, asset identifier, package, normalized name, software identity, or PURL.',
    typeLabel: 'String property'
  }
];
