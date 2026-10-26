#!/usr/bin/env node
// Serves one built artifact folder until stopped: node e2e/serve-cli.mjs <ui2|legacy>
import { existsSync } from 'node:fs';
import { ARTIFACTS, serveArtifact } from './serve.mjs';

const version = process.argv[2];
if (!ARTIFACTS[version]) {
  console.error(`Usage: node e2e/serve-cli.mjs <${Object.keys(ARTIFACTS).join('|')}>`);
  process.exit(2);
}
if (!existsSync(ARTIFACTS[version].dir)) {
  console.error(`${ARTIFACTS[version].dir} is missing; run npm run e2e:build first.`);
  process.exit(1);
}
const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
console.log(`${version} artifact served at ${server.url}`);
