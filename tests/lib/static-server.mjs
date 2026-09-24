/**
 * Minimal static file server for the built site (tests only, no dependencies).
 * Serves site/dist with Astro's directory-format rules and a 404.html fallback.
 */
import http from 'node:http';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.xml': 'application/xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

export function startServer(distDir, port) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    let filePath = join(distDir, decodeURIComponent(url.pathname));

    if (existsSync(filePath) && statSync(filePath).isDirectory()) {
      filePath = join(filePath, 'index.html');
    }
    if (!existsSync(filePath) && existsSync(filePath + '.html')) {
      filePath += '.html';
    }
    if (!existsSync(filePath)) {
      const notFound = join(distDir, '404.html');
      res.writeHead(404, { 'Content-Type': TYPES['.html'] });
      res.end(existsSync(notFound) ? readFileSync(notFound) : 'Not found');
      return;
    }
    const ext = filePath.slice(filePath.lastIndexOf('.'));
    res.writeHead(200, { 'Content-Type': TYPES[ext] || 'application/octet-stream' });
    res.end(readFileSync(filePath));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

export function stopServer(server) {
  return new Promise((resolve) => server.close(resolve));
}
