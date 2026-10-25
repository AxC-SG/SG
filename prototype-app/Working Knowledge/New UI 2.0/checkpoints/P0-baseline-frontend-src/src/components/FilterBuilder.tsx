import React from 'react';

export type FilterBuilderCategory = {
  key: string;
  label: string;
  disabled?: boolean;
};

export type FilterBuilderField = {
  key: string;
  label: string;
  categoryKey: string;
  description: string;
  typeLabel: string;
};

type Props = {
  categories: FilterBuilderCategory[];
  fields: FilterBuilderField[];
  activeKeys: string[];
  onAddFilter: (key: string) => void;
};

export function FilterBuilder({ categories, fields, activeKeys, onAddFilter }: Props) {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState('');
  const [activeCategory, setActiveCategory] = React.useState<string>(
    categories.find((item) => !item.disabled)?.key ?? categories[0]?.key ?? ''
  );
  const rootRef = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent): void => {
      const target = event.target as Node | null;
      if (!target) return;
      if (!rootRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const onEscape = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onEscape);
    };
  }, [open]);

  const searchValue = search.trim().toLowerCase();
  const visibleFields = fields.filter((field) => {
    if (activeCategory && field.categoryKey !== activeCategory) {
      return false;
    }
    if (!searchValue) {
      return true;
    }
    return (
      field.label.toLowerCase().includes(searchValue) ||
      field.description.toLowerCase().includes(searchValue)
    );
  });

  const addFilter = (key: string): void => {
    onAddFilter(key);
  };

  return (
    <div className={open ? 'filter-builder open' : 'filter-builder'} ref={rootRef}>
      <button
        type="button"
        className="filter-builder-trigger"
        onClick={() => setOpen((current) => !current)}
      >
        <span className="filter-builder-plus" aria-hidden="true">+</span>
        <span>Filter</span>
      </button>

      {open && (
        <div className="filter-builder-panel">
          <div className="filter-builder-search">
            <span className="filter-builder-search-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <circle cx="10.5" cy="10.5" r="6.5" />
                <path d="m15.4 15.4 5.1 5.1" />
              </svg>
            </span>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search..."
            />
            <button type="button" className="filter-builder-info" aria-label="Filter help">i</button>
          </div>

          <div className="filter-builder-layout">
            <div className="filter-builder-categories">
              {categories.map((category) => (
                <button
                  key={category.key}
                  type="button"
                  className={category.key === activeCategory ? 'filter-builder-category active' : 'filter-builder-category'}
                  disabled={category.disabled}
                  onClick={() => {
                    if (!category.disabled) {
                      setActiveCategory(category.key);
                    }
                  }}
                >
                  {category.label}
                </button>
              ))}
            </div>

            <div className="filter-builder-fields">
              {visibleFields.length === 0 && (
                <div className="filter-builder-empty">No fields found.</div>
              )}
              {visibleFields.map((field) => {
                const added = activeKeys.includes(field.key);
                return (
                  <button
                    key={field.key}
                    type="button"
                    className={added ? 'filter-builder-field active' : 'filter-builder-field'}
                    onClick={() => addFilter(field.key)}
                  >
                    <span className="filter-builder-field-label-wrap">
                      <span className="filter-builder-field-label">{field.label}</span>
                      <span className="filter-builder-field-meta">{field.description}</span>
                    </span>
                    <span className="filter-builder-field-state">{added ? 'Added' : 'Add'}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
