#!/usr/bin/env node
// Verifies a checkpoint archive against its per-file manifest (path and sha256).
// Extracts into a scratch folder, so the archive itself is never modified. This is an archive
// integrity check for the retained source baseline and frozen rollback build.
//
// Usage: node e2e/verify-archive.mjs [manifest.json]
// Default: checkpoints/P0-baseline-frontend-src-manifest.json
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checkpoints = path.resolve(frontend, '../Working Knowledge/New UI 2.0/checkpoints');
const manifestFile = path.resolve(process.argv[2] ?? path.join(checkpoints, 'P0-baseline-frontend-src-manifest.json'));
const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
const archive = path.join(path.dirname(manifestFile), manifest.artifact);

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const full = path.join(dir, name);
  return statSync(full).isDirectory() ? walk(full) : [full];
});

const failures = [];
if (sha256(archive) !== manifest.sha256) failures.push(`archive checksum mismatch: ${manifest.artifact}`);

const scratch = mkdtempSync(path.join(os.tmpdir(), 'verify-archive-'));
try {
  const extract = spawnSync('tar', ['-xzf', archive, '-C', scratch], { stdio: 'inherit' });
  if (extract.status !== 0) throw new Error('tar extraction failed');
  // The source archive has a named root; the frozen build manifest uses paths from tar root.
  const root = path.join(scratch, manifest.root ?? '.');
  const actual = new Map(walk(root).map((file) => [path.relative(root, file).split(path.sep).join('/'), file]));
  for (const { path: rel, sha256: expected } of manifest.files) {
    const file = actual.get(rel);
    if (!file) failures.push(`missing: ${rel}`);
    else if (sha256(file) !== expected) failures.push(`sha256 mismatch: ${rel}`);
    actual.delete(rel);
  }
  for (const rel of actual.keys()) failures.push(`unlisted: ${rel}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

if (failures.length) {
  console.error(failures.join('\n'));
  console.error(`verify-archive FAILED: ${failures.length} problem(s)`);
  process.exit(1);
}
console.log(`verify-archive OK: ${manifest.files.length} files match ${manifest.artifact}`);
