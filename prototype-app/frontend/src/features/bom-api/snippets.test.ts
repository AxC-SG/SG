import { describe, expect, it } from 'vitest';
import { buildSnippets } from './snippets';

const input = { baseUrl: 'https://api.example.test/api', bomType: 'SBOM' as const, fileName: 'bom.json' };

describe('buildSnippets', () => {
  it('posts the file as the raw body with the key read from a secret', () => {
    const { curl } = buildSnippets(input);

    expect(curl).toContain('POST "https://api.example.test/api/bom/ingest?bomType=SBOM&pipeline=ci&buildId=$BUILD_ID"');
    expect(curl).toContain('Authorization: Bearer $SCOUTGRID_INGEST_KEY');
    expect(curl).toContain('Content-Type: application/json');
    expect(curl).toContain('--data-binary @bom.json');
    expect(curl).not.toMatch(/sgk_[0-9a-f]/);
  });

  it('sends XML documents with an XML content type', () => {
    const { curl } = buildSnippets({ ...input, fileName: 'sbom.spdx.xml' });

    expect(curl).toContain('Content-Type: application/xml');
    expect(curl).toContain('--data-binary @sbom.spdx.xml');
  });

  it('uses each system\'s own build and repository variables for the build id and correlator', () => {
    const snippets = buildSnippets({ ...input, bomType: 'AI_BOM' });

    expect(snippets.github).toContain('bomType=AI_BOM&pipeline=github-actions&buildId=${{ github.run_id }}&correlator=${{ github.repository }}');
    expect(snippets.github).toContain('SCOUTGRID_INGEST_KEY: ${{ secrets.SCOUTGRID_INGEST_KEY }}');
    expect(snippets.gitlab).toContain('pipeline=gitlab-ci&buildId=$CI_PIPELINE_ID&correlator=$CI_PROJECT_PATH');
    expect(snippets.jenkins).toContain("credentialsId: 'scoutgrid-ingest-key'");
    expect(snippets.jenkins).toContain('pipeline=jenkins&buildId=${BUILD_ID}&correlator=${JOB_NAME}');
  });

  it('keeps every continuation line attached to the command', () => {
    const lines = buildSnippets(input).curl.split('\n');

    expect(lines).toHaveLength(4);
    expect(lines.slice(0, -1).every((line) => line.endsWith(' \\'))).toBe(true);
  });
});
