import type { BomType } from '../../api/client';

export type PipelineKind = 'curl' | 'github' | 'gitlab' | 'jenkins';

export const PIPELINE_LABELS: Record<PipelineKind, string> = {
  curl: 'curl',
  github: 'GitHub Actions',
  gitlab: 'GitLab CI',
  jenkins: 'Jenkins',
};

type SnippetInput = {
  baseUrl: string;
  bomType: BomType;
  // The file the pipeline already produced; XML is sent with an XML Content-Type.
  fileName: string;
};

function contentTypeFor(fileName: string): string {
  return fileName.toLowerCase().endsWith('.xml') ? 'application/xml' : 'application/json';
}

function pushCommand(
  { baseUrl, bomType, fileName }: SnippetInput,
  query: { pipeline: string; buildId: string; correlator?: string },
  indent: string,
): string {
  const params = [
    `bomType=${bomType}`,
    `pipeline=${query.pipeline}`,
    `buildId=${query.buildId}`,
    ...(query.correlator ? [`correlator=${query.correlator}`] : []),
  ].join('&');
  return [
    `curl --fail-with-body -sS -X POST "${baseUrl}/bom/ingest?${params}"`,
    `  -H "Authorization: Bearer $SCOUTGRID_INGEST_KEY"`,
    `  -H "Content-Type: ${contentTypeFor(fileName)}"`,
    `  --data-binary @${fileName}`,
  ].join(` \\\n${indent}`);
}

/** Copy-ready pipeline steps. The key is always read from a secret, never inlined. */
export function buildSnippets(input: SnippetInput): Record<PipelineKind, string> {
  const curl = pushCommand(input, { pipeline: 'ci', buildId: '$BUILD_ID' }, '');
  const github = [
    '- name: Publish BOM to Scoutgrid',
    '  env:',
    '    SCOUTGRID_INGEST_KEY: ${{ secrets.SCOUTGRID_INGEST_KEY }}',
    '  run: |',
    `    ${pushCommand(
      input,
      { pipeline: 'github-actions', buildId: '${{ github.run_id }}', correlator: '${{ github.repository }}' },
      '    ',
    )}`,
  ].join('\n');
  const gitlab = [
    'publish-bom:',
    '  stage: deploy',
    '  script:',
    `    - ${pushCommand(
      input,
      { pipeline: 'gitlab-ci', buildId: '$CI_PIPELINE_ID', correlator: '$CI_PROJECT_PATH' },
      '      ',
    )}`,
    '  variables:',
    '    SCOUTGRID_INGEST_KEY: $SCOUTGRID_INGEST_KEY',
  ].join('\n');
  const jenkins = [
    "withCredentials([string(credentialsId: 'scoutgrid-ingest-key', variable: 'SCOUTGRID_INGEST_KEY')]) {",
    "  sh '''",
    `  ${pushCommand(
      input,
      { pipeline: 'jenkins', buildId: '${BUILD_ID}', correlator: '${JOB_NAME}' },
      '  ',
    )}`,
    "  '''",
    '}',
  ].join('\n');
  return { curl, github, gitlab, jenkins };
}
