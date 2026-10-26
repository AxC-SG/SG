// Minimal static server for one copied build folder, with the SPA fallback vercel.json applies.
// Each UI version gets its own folder and port so a run can never pick up the other build.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.txt': 'text/plain; charset=utf-8', '.webmanifest': 'application/manifest+json',
};

async function isFile(file) {
  try {
    return (await stat(file)).isFile();
  } catch {
    return false;
  }
}

/** Serves `root` on 127.0.0.1:`port`; resolves with `{ url, close }` once listening. */
export function serveArtifact(root, port) {
  const base = path.resolve(root);
  const server = createServer(async (request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
    const candidate = path.resolve(base, `.${pathname}`);
    const inside = candidate === base || candidate.startsWith(base + path.sep);
    const file = inside && await isFile(candidate) ? candidate : path.join(base, 'index.html');
    response.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    response.end(await readFile(file));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise((done) => server.close(done)),
    }));
  });
}

const here = path.dirname(fileURLToPath(import.meta.url));

export const ARTIFACTS = {
  ui2: { dir: path.join(here, '.artifacts', 'ui2'), port: 5175 },
  legacy: { dir: path.join(here, '.artifacts', 'legacy'), port: 5176 },
};
