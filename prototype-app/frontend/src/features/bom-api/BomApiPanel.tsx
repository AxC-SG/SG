import type { BomType } from '../../api/client';
import { BomIngestKeysSection } from './BomIngestKeysSection';
import { BomPipelinePushes } from './BomPipelinePushes';
import { BomPipelineSnippets } from './BomPipelineSnippets';

/** Pushing BOMs from CI/CD: the keys a pipeline authenticates with, how to call the API, and what arrived. */
export function BomApiPanel({ bomType }: { bomType?: BomType }) {
  return (
    <section className="panel" aria-labelledby="bom-api-heading">
      <div className="panel-header">
        <h3 id="bom-api-heading">CI/CD pipeline API</h3>
        <span className="panel-caption">
          Push SBOM, AI BOM, CBOM or Vendor BOM documents from your pipeline. CycloneDX (JSON, XML) and SPDX (JSON, XML).
        </span>
      </div>
      <div className="ingestion-form">
        <BomIngestKeysSection />
        <BomPipelineSnippets initialBomType={bomType} />
        <BomPipelinePushes />
      </div>
    </section>
  );
}
