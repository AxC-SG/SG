import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';
import process from 'node:process';
import { loadEnv } from 'vite';
import { staticAuthenticationVariables } from './production-auth-policy.mjs';

const forbidden = [
  'change-me-in-prod',
  'local-creator',
  'local-analyst',
  'VITE_OPENAI_API_KEY',
  'api.openai.com/v1/chat/completions',
];
const providerSecretPatterns = [
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\bAIza[A-Za-z0-9_-]{30,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
];
const configured = loadEnv(process.env.MODE ?? 'production', fileURLToPath(new URL('..', import.meta.url)), 'VITE_');
const configuredSecrets = staticAuthenticationVariables.map((name) => configured[name]).filter((value) => value?.trim());

async function files(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  }));
  return nested.flat();
}

const violations = [];
for (const path of await files(fileURLToPath(new URL('../dist', import.meta.url)))) {
  const content = await readFile(path, 'utf8').catch(() => '');
  if (configuredSecrets.some((value) => content.includes(value))) violations.push(`${path}: configured static authentication input`);
  for (const value of forbidden) {
    if (content.includes(value)) violations.push(`${path}: ${value}`);
  }
  for (const pattern of providerSecretPatterns) {
    if (pattern.test(content)) violations.push(`${path}: provider secret matching ${pattern}`);
    pattern.lastIndex = 0;
  }
}
if (violations.length > 0) {
  throw new Error(`Production bundle contains development credentials:\n${violations.join('\n')}`);
}
