import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../prototype-app/policy-packages/', import.meta.url));
const required = ['policyId', 'version', 'name', 'description', 'severity', 'workflowClass', 'defaultSelection', 'artifactTypes', 'requiredResourceFamilies', 'requiredFacts', 'predicate', 'reasonCode', 'remediation', 'frameworkMappings', 'packageSourceRef'];
const files = [];
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    // The governed Phase 1 AGCF catalog has its own schema and validator
    // (scripts/compile-ai-grid-phase1.mjs); this legacy validator only covers
    // the original flat-shape example packages.
    if (entry.isDirectory() && entry.name === 'agcf') continue;
    // This repository-level governance manifest describes legacy-to-AGCF parity;
    // it is not itself a policy package.
    if (!entry.isDirectory() && entry.name === 'legacy-policy-parity.json') continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.name.endsWith('.json')) files.push(path);
  }
}
await walk(root);
for (const file of files) {
  const policy = JSON.parse(await readFile(file, 'utf8'));
  const missing = required.filter((field) => policy[field] == null || policy[field] === '');
  if (missing.length) throw new Error(`${file}: missing ${missing.join(', ')}`);
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(policy.severity)) throw new Error(`${file}: invalid severity`);
  if (!['POSTURE_FINDING', 'EXPOSURE_HYPOTHESIS', 'VALIDATED_EXPOSURE'].includes(policy.workflowClass)) throw new Error(`${file}: invalid workflowClass`);
  if (!Array.isArray(policy.artifactTypes) || !Array.isArray(policy.requiredFacts) || typeof policy.predicate !== 'object') throw new Error(`${file}: invalid policy shape`);
  if (policy.parameterDefinitions != null && !Array.isArray(policy.parameterDefinitions)) throw new Error(`${file}: parameterDefinitions must be an array`);
}
console.log(`Validated ${files.length} policy package(s).`);
