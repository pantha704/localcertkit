/**
 * Axe evidence — scans every built page with the AccessProof engine
 * (../accessproof/engine, same axe-core + WCAG 2.2 A/AA tags used there) and
 * records per-page violation counts. Requirement: 0 violations on every page.
 *
 * Writes tests/out/axe-results.json. Engine's full HTML/MD reports go to a
 * temp dir (not committed).
 *
 * Usage: node tests/axe-scan.mjs
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, stopServer } from './lib/static-server.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'site', 'dist');
const engineCli = resolve(root, '..', 'accessproof', 'engine', 'cli.js');

if (!existsSync(join(dist, 'index.html'))) {
  console.error('site/dist is not built — run `cd site && bun run build` first.');
  process.exit(2);
}
if (!existsSync(engineCli)) {
  console.error('AccessProof engine not found at ' + engineCli);
  process.exit(2);
}

const PORT = Number(process.env.AXE_PORT || 4400);
const BASE = `http://127.0.0.1:${PORT}`;

const PAGES = [
  { path: '/', slug: 'home' },
  { path: '/pfx-to-pem/', slug: 'pfx-to-pem' },
  { path: '/pem-to-pfx/', slug: 'pem-to-pfx' },
  { path: '/certificate-decoder/', slug: 'certificate-decoder' },
  { path: '/csr-decoder/', slug: 'csr-decoder' },
  { path: '/key-cert-match/', slug: 'key-cert-match' },
  { path: '/chain-order/', slug: 'chain-order' },
  { path: '/der-jwk-inspector/', slug: 'der-jwk-inspector' },
  { path: '/privacy/', slug: 'privacy' },
  { path: '/about/', slug: 'about' },
  { path: '/roadmap/', slug: 'roadmap' },
  { path: '/this-page-does-not-exist/', slug: '404' },
];

function runEngine(url, outDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [engineCli, 'scan', url, '--max-pages', '1', '--out', outDir, '--json-only'],
      { cwd: dirname(engineCli), stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`engine exit ${code}: ${stderr.slice(0, 300)}`));
      else resolve({ stdout, stderr });
    });
  });
}

const server = await startServer(dist, PORT);
const tmp = mkdtempSync(join(tmpdir(), 'certkit-axe-'));
mkdirSync(join(root, 'tests', 'out'), { recursive: true });

const rows = [];
for (const p of PAGES) {
  const url = `${BASE}${p.path}`;
  const outDir = join(tmp, p.slug);
  mkdirSync(outDir, { recursive: true });
  try {
    await runEngine(url, outDir);
    const report = JSON.parse(readFileSync(join(outDir, 'report.json'), 'utf8'));
    const page = report.pages && report.pages[0];
    const violations = (page && page.axe && page.axe.violations) || [];
    const row = {
      page: p.path,
      slug: p.slug,
      status: page ? page.status : null,
      title: page ? page.title : null,
      violations: violations.length,
      violationIds: violations.map((v) => v.id),
      impactCounts: report.summary?.totals || null,
      axeError: page && page.axe && page.axe.error ? page.axe.error : null,
      enginePageError: page ? page.error : null,
    };
    rows.push(row);
    console.log(
      `${row.violations === 0 ? 'CLEAN' : 'ISSUES'}  ${p.path}  status=${row.status}  violations=${row.violations}` +
        (row.violationIds.length ? '  → ' + row.violationIds.join(', ') : '')
    );
  } catch (e) {
    rows.push({ page: p.path, slug: p.slug, violations: null, error: e.message });
    console.log(`ERROR  ${p.path}  ${e.message}`);
  }
}

const failed = rows.filter((r) => r.violations !== 0);
const summary = {
  engine: '../../accessproof/engine (axe-core, WCAG 2.2 A/AA tags)',
  scannedAt: new Date().toISOString(),
  baseUrl: BASE,
  totalPages: rows.length,
  cleanPages: rows.length - failed.length,
  pagesWithViolations: failed.length,
  rows,
  rawReportsDir: tmp,
};
writeFileSync(join(root, 'tests', 'out', 'axe-results.json'), JSON.stringify(summary, null, 2));
await stopServer(server);

console.log(`\n${summary.cleanPages}/${rows.length} pages clean — wrote tests/out/axe-results.json`);
if (failed.length) process.exit(1);
