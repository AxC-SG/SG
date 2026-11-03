import React from 'react';
import { absoluteApiBase, type BomType } from '../../api/client';
import { buildSnippets, PIPELINE_LABELS, type PipelineKind } from './snippets';

const KINDS = Object.keys(PIPELINE_LABELS) as PipelineKind[];

const BOM_TYPE_OPTIONS: Array<{ value: BomType; label: string }> = [
  { value: 'SBOM', label: 'SBOM' }, { value: 'CBOM', label: 'CBOM' }, { value: 'AI_BOM', label: 'AI BOM' }, { value: 'VENDOR', label: 'Vendor BOM' },
];

type Props = { initialBomType?: BomType };

export function BomPipelineSnippets({ initialBomType = 'SBOM' }: Props) {
  const [bomType, setBomType] = React.useState<BomType>(initialBomType);
  const [kind, setKind] = React.useState<PipelineKind>('curl');
  const [fileName, setFileName] = React.useState('bom.json');
  const [copied, setCopied] = React.useState(false);

  const snippet = React.useMemo(
    () => buildSnippets({ baseUrl: absoluteApiBase(), bomType, fileName: fileName.trim() || 'bom.json' })[kind],
    [bomType, fileName, kind],
  );

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the snippet stays selectable on screen.
      setCopied(false);
    }
  };

  return (
    <div className="form-section">
      <p className="form-section-title">Add it to your pipeline</p>
      <p className="panel-caption">
        Store the key as a secret named <code>SCOUTGRID_INGEST_KEY</code>. Pushing again from the same
        pipeline replaces the previous version; add <code>correlator</code> to give a pipeline its own identity
        (for example one per matrix job). Re-sending identical content is a no-op, so retries are safe.
      </p>
      <div className="ingestion-mode-tabs" role="tablist" aria-label="Pipeline type">
        {KINDS.map((item) => (
          <button
            key={item}
            type="button"
            role="tab"
            aria-selected={kind === item}
            className={`connect-filter-btn${kind === item ? ' active' : ''}`}
            onClick={() => setKind(item)}
          >
            {PIPELINE_LABELS[item]}
          </button>
        ))}
      </div>
      <label className="form-label" style={{ marginTop: 8 }}>BOM type your pipeline pushes
        <select className="form-input" value={bomType} onChange={(event) => setBomType(event.target.value as BomType)}>
          {BOM_TYPE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </label>
      <label className="form-label" style={{ marginTop: 8 }}>BOM file your pipeline produces
        <input
          type="text"
          className="form-input"
          value={fileName}
          onChange={(event) => setFileName(event.target.value)}
          placeholder="bom.json or bom.xml"
        />
      </label>
      <pre className="mono" style={{ overflowX: 'auto', padding: 12, marginTop: 8 }} aria-label={`${PIPELINE_LABELS[kind]} snippet`}>
        {snippet}
      </pre>
      <button type="button" className="btn btn-secondary btn-sm" onClick={() => void copy()}>
        {copied ? 'Copied' : 'Copy snippet'}
      </button>
    </div>
  );
}
