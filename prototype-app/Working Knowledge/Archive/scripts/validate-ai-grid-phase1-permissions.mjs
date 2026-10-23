import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
const backendRoot = join(repositoryRoot, 'prototype-app', 'backend');
const awsSourceRoot = join(backendRoot, 'src', 'main', 'java', 'com', 'prototype', 'vulnwatch', 'aisecurity', 'aws');
const awsPolicyPath = join(backendRoot, 'src', 'main', 'resources', 'ai-security', 'permissions', 'scout-ai-inventory-readonly-v2.json');
const azureMatrixPath = join(backendRoot, 'src', 'main', 'resources', 'ai-security', 'azure-policy-permission-matrix.yaml');
const azureRolePath = join(backendRoot, 'src', 'main', 'resources', 'ai-security', 'permissions', 'scout-azure-ai-search-definition-reader-v1.json');
const reportPath = join(repositoryRoot, 'prototype-app', 'docs', 'ai-grid-phase-1-permission-delta.md');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : entry.name.endsWith('.java') ? [path] : [];
  }));
  return nested.flat();
}

function awsActionsFromSource(source) {
  return new Set([...source.matchAll(/"([a-z0-9-]+:[A-Za-z][A-Za-z0-9]*)"/g)].map((match) => match[1]));
}

function azureActionsFromMatrix(matrix) {
  const actions = new Set();
  const lines = matrix.split('\n');
  for (let index = 0; index < lines.length; index++) {
    const inline = lines[index].match(/^\s+actions:\s*\[([^\]]*)\]\s*$/);
    if (inline) {
      inline[1].split(',').map((action) => action.trim()).filter(Boolean).forEach((action) => actions.add(action));
      continue;
    }
    if (!/^\s+actions:\s*$/.test(lines[index])) continue;
    const indentation = lines[index].match(/^(\s*)/)[1].length;
    for (index += 1; index < lines.length; index++) {
      const line = lines[index];
      if (!line.trim()) continue;
      if (line.match(/^(\s*)/)[1].length <= indentation) {
        index -= 1;
        break;
      }
      const action = line.match(/^\s+-\s+(Microsoft\.[^\s]+)\s*$/);
      if (action) actions.add(action[1]);
    }
  }
  return actions;
}

function isReadOnlyAws(action) {
  return /:(Get|List|Describe)/.test(action);
}

function isReadOnlyAzure(action) {
  return action.endsWith('/read');
}

async function main() {
  const [sourceFiles, awsPolicyBytes, azureMatrix, azureRoleBytes] = await Promise.all([
    files(awsSourceRoot), readFile(awsPolicyPath, 'utf8'), readFile(azureMatrixPath, 'utf8'), readFile(azureRolePath, 'utf8'),
  ]);
  const source = (await Promise.all(sourceFiles.map((file) => readFile(file, 'utf8')))).join('\n');
  const awsUsed = awsActionsFromSource(source);
  const awsProhibited = new Set([
    'iam:CreateAccessKey', 'iam:UpdateAccessKey', 'iam:DeleteAccessKey', 'iam:PassRole',
    'cloudformation:*', 'cloudtrail:PutEventSelectors', 'logs:Put*', 's3:Put*', 's3:Delete*', 'xray:Put*',
  ]);
  awsProhibited.forEach((action) => awsUsed.delete(action));
  const awsPolicy = JSON.parse(awsPolicyBytes);
  const awsAllowed = new Set(awsPolicy.Statement.flatMap((statement) => statement.Action ?? []));
  const missingAws = [...awsUsed].filter((action) => !awsAllowed.has(action)).sort();
  assert(missingAws.length === 0, `AWS permission policy is missing implemented actions: ${missingAws.join(', ')}`);
  assert([...awsAllowed].every((action) => !awsProhibited.has(action)),
    'AWS permission policy contains an explicitly prohibited mutation action');
  assert([...awsAllowed].every(isReadOnlyAws), 'AWS permission policy must contain only Get, List, or Describe actions');

  const azureActions = azureActionsFromMatrix(azureMatrix);
  assert(azureActions.size > 0, 'Azure permission matrix must declare read actions');
  assert([...azureActions].every(isReadOnlyAzure), 'Azure permission matrix must contain only management-plane read actions');
  for (const prohibited of [
    'Microsoft.CognitiveServices/accounts/listKeys/action',
    'Microsoft.Search/searchServices/listAdminKeys/action',
    'Microsoft.Search/searchServices/listQueryKeys/action',
    'Microsoft.Search/searchServices/indexes/documents/read',
    'Microsoft.Authorization/roleAssignments/write',
  ]) assert(azureMatrix.includes(prohibited), `Azure matrix must prohibit ${prohibited}`);
  const azureRole = JSON.parse(azureRoleBytes);
  assert((azureRole.DataActions ?? []).length === 0 && (azureRole.NotDataActions ?? []).includes('*'),
    'Azure Search definition role must deny all data-plane actions');
  assert((azureRole.Actions ?? []).every(isReadOnlyAzure), 'Azure Search definition role must contain only read actions');

  const report = `# AI Grid Phase 1 permission delta\n\nGenerated by scripts/validate-ai-grid-phase1-permissions.mjs. This is an access-contract audit, not provider-side authorization evidence.\n\n| Provider | Contract result | Detail |\n| --- | --- | --- |\n| AWS | PASS | ${awsUsed.size} implemented string-declared actions are present in the ${awsAllowed.size}-action read-only policy. |\n| Azure | PASS | ${azureActions.size} matrix actions are management-plane read; the Search definition role has no data actions and explicitly denies them. |\n\nThe contract denies write, key-listing, and document-content access. Golden-account permission validation remains a separate release gate.\n\n## Artifact digests\n\n- AWS policy: ${sha256(awsPolicyBytes)}\n- Azure matrix: ${sha256(azureMatrix)}\n- Azure Search role: ${sha256(azureRoleBytes)}\n`;
  if (process.argv.includes('--write')) {
    await mkdir(join(repositoryRoot, 'prototype-app', 'docs'), { recursive: true });
    await writeFile(reportPath, report);
  }
  console.log(`Validated AI Grid Phase 1 permission contracts (AWS ${awsUsed.size} implemented actions; Azure ${azureActions.size} read actions).`);
}

await main();
