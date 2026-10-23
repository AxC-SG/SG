import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const platformV1 = await readFile(join(root, 'prototype-app/backend/src/main/resources/db/migration/postgres_reset/V1__platform_schema.sql'), 'utf8');
const platformV2 = await readFile(join(root, 'prototype-app/backend/src/main/resources/db/migration/postgres_reset/V2__remove_legacy_ai_grid_migration.sql'), 'utf8');
const tenantV2 = await readFile(join(root, 'prototype-app/backend/src/main/resources/db/migration/tenant/V2__remove_legacy_ai_grid_migration_data.sql'), 'utf8');
const ledger = [...platformV1.matchAll(/INSERT INTO platform\.ai_grid_policy_migration_ledger[\s\S]*?VALUES \('([^']+)'/g)].map((match) => match[1]);
const ids = (sql) => [...sql.matchAll(/AWS_[A-Z0-9_]+/g)].map((match) => match[0]);
const sameSet = (actual, expected) => actual.size === expected.size && [...actual].every((id) => expected.has(id));
const expected = new Set(ledger);
if (!sameSet(new Set(ids(platformV2)), expected) || !sameSet(new Set(ids(tenantV2)), expected)) {
  throw new Error(`Legacy cleanup IDs diverge from V1 ledger (expected: ${[...expected].sort().join(', ')})`);
}
console.log(`Validated ${expected.size} legacy AI Grid cleanup IDs against the V1 ledger.`);
