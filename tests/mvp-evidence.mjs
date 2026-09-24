/**
 * Gate-1 MVP evidence harness — drives the BUILT static site in headless Chromium
 * against the spike fixtures. Every tool gets a happy path and an error path;
 * exported artifacts are round-tripped through node-forge/OpenSSL-compatible code
 * in Node so the results are verified, not just rendered.
 *
 * Writes tests/out/mvp-results.json.
 *
 * Usage:  node tests/mvp-evidence.mjs          (expects site/dist to be built)
 *         PORT=4399 CHROME_PATH=… node …        (overrides)
 */
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, stopServer } from './lib/static-server.mjs';

const require = createRequire(import.meta.url);
const forge = require('node-forge');

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'site', 'dist');
const fixtures = (p) => join(root, 'fixtures', p);
const fixtureText = (p) => readFileSync(fixtures(p), 'utf8');

if (!existsSync(join(dist, 'index.html'))) {
  console.error('site/dist is not built — run `cd site && bun run build` first.');
  process.exit(2);
}

const PORT = Number(process.env.PORT || 4399);
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME =
  process.env.CHROME_PATH ||
  `${process.env.HOME}/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome`;
if (!existsSync(CHROME)) throw new Error('chromium not found at ' + CHROME);

mkdirSync(join(root, 'tests', 'out'), { recursive: true });
const tmpPfx = join(root, 'tests', 'out', 'mvp-created.p12');
rmSync(tmpPfx, { force: true });

const server = await startServer(dist, PORT);
const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
const context = await browser.newContext({ acceptDownloads: true });
const page = await context.newPage();

let consoleErrors = [];
let pageErrors = [];
page.on('console', (m) => {
  if (m.type() === 'error') consoleErrors.push(m.text());
});
page.on('pageerror', (e) => pageErrors.push(String(e)));

const results = [];
const only = process.env.ONLY || '';

async function testCase(name, fn) {
  if (only && !name.includes(only)) return;
  consoleErrors = [];
  pageErrors = [];
  const t0 = Date.now();
  const row = { name, ok: false, ms: 0, consoleErrors: [], pageErrors: [], details: {} };
  try {
    await page.goto('about:blank');
    const details = await fn();
    row.details = details instanceof Object ? details : { value: details };
    row.ok = true;
  } catch (e) {
    row.error = e.message;
  }
  row.ms = Date.now() - t0;
  row.consoleErrors = consoleErrors.slice();
  row.pageErrors = pageErrors.slice();
  if (row.consoleErrors.length || row.pageErrors.length) {
    row.ok = false;
    row.error = (row.error ? row.error + ' | ' : '') + 'console/page errors present';
  }
  results.push(row);
  console.log(`${row.ok ? 'PASS' : 'FAIL'}  ${name}  (${row.ms} ms)${row.ok ? '' : '  → ' + (row.error || '')}`);
}

const assert = (cond, msg) => {
  if (!cond) throw new Error(msg || 'assertion failed');
};

async function expectError(pattern) {
  await page.waitForSelector('#tool-error:not([hidden])', { timeout: 15000 });
  const text = await page.locator('#tool-error').innerText();
  assert(pattern.test(text), `error text did not match ${pattern}: "${text.slice(0, 200)}"`);
  return text;
}

async function expectResults() {
  await page.waitForSelector('#results:not([hidden])', { timeout: 20000 });
}

// ---------------------------------------------------------------- pfx-to-pem

await testCase('pfx-to-pem: modern AES-256 file → key + cert + match', async () => {
  await page.goto(`${BASE}/pfx-to-pem/`);
  await page.setInputFiles('#pfx-file', fixtures('modern-aes256.p12'));
  await page.fill('#pfx-password', 'modernpass');
  await page.click('#pfx-run');
  await expectResults();

  const keyPem = await page.inputValue('#out-key');
  const certPem = await page.inputValue('#out-certs');
  const badge = await page.locator('#match-badge').innerText();
  assert(/BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY/.test(keyPem), 'key PEM missing');
  assert(/BEGIN CERTIFICATE/.test(certPem), 'cert PEM missing');
  assert(/matches certificate/i.test(badge), 'match badge: ' + badge);

  // independent Node round-trip
  const priv = forge.pki.privateKeyFromPem(keyPem);
  const cert = forge.pki.certificateFromPem(certPem);
  const modulusEqual =
    priv.n.compareTo(cert.publicKey.n) === 0 && priv.e.compareTo(cert.publicKey.e) === 0;
  assert(modulusEqual, 'exported key/cert do not match in Node');
  const sig = priv.sign(forge.md.sha256.create().update('x'));
  const md = forge.md.sha256.create();
  md.update('x');
  assert(cert.publicKey.verify(md.digest().bytes(), sig), 'exported signature does not verify');
  return { keyLength: keyPem.length, certs: (certPem.match(/BEGIN CERTIFICATE/g) || []).length };
});

await testCase('pfx-to-pem: wrong password → clear error', async () => {
  await page.goto(`${BASE}/pfx-to-pem/`);
  await page.setInputFiles('#pfx-file', fixtures('modern-aes256.p12'));
  await page.fill('#pfx-password', 'WRONG-PASSWORD');
  await page.click('#pfx-run');
  const text = await expectError(/password/i);
  const resultsHidden = await page.locator('#results').isHidden();
  assert(resultsHidden, 'results should stay hidden on error');
  return { error: text.slice(0, 90) };
});

await testCase('pfx-to-pem: EC file → friendly unsupported + roadmap link', async () => {
  await page.goto(`${BASE}/pfx-to-pem/`);
  await page.setInputFiles('#pfx-file', fixtures('ec-p256-aes256.p12'));
  await page.fill('#pfx-password', 'ecpass');
  await page.click('#pfx-run');
  const text = await expectError(/EC|Ed25519/i);
  const link = page.locator('#tool-error a[href="/roadmap/"]');
  assert((await link.count()) === 1, 'roadmap link missing');
  return { error: text.slice(0, 80) };
});

// ---------------------------------------------------------------- pem-to-pfx

await testCase('pem-to-pfx: leaf key + chain → downloadable PFX, forge-verified', async () => {
  await page.goto(`${BASE}/pem-to-pfx/`);
  await page.fill('#key-pem', fixtureText('pem/leaf-key.pem'));
  await page.fill('#cert-pems', fixtureText('pem/chain.pem'));
  await page.fill('#pfx-password', 'gate2pass');
  await page.fill('#friendly-name', 'mvp test');
  await page.click('#pfx-run');
  await expectResults();

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#download-pfx'),
  ]);
  await download.saveAs(tmpPfx);
  const bytes = readFileSync(tmpPfx);
  assert(bytes[0] === 0x30, 'PFX does not start with a SEQUENCE');

  const p12 = forge.pkcs12.pkcs12FromAsn1(
    forge.asn1.fromDer(forge.util.createBuffer(bytes.toString('binary'))),
    'gate2pass'
  );
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
  assert(keyBags.length === 1, 'expected 1 key bag');
  assert(certBags.length === 2, 'expected 2 cert bags, got ' + certBags.length);
  const match = keyBags[0].key.n.compareTo(certBags[0].cert.publicKey.n) === 0;
  assert(match, 'round-tripped key does not match leaf cert');
  return { pfxBytes: bytes.length, certBags: certBags.length };
});

await testCase('pem-to-pfx: mismatched key/cert → refused with hint', async () => {
  await page.goto(`${BASE}/pem-to-pfx/`);
  await page.fill('#key-pem', fixtureText('pem/modern-key.pem'));
  await page.fill('#cert-pems', fixtureText('pem/leaf-cert.pem'));
  await page.fill('#pfx-password', 'gate2pass');
  await page.click('#pfx-run');
  const text = await expectError(/does not match/i);
  assert((await page.locator('#tool-error a[href="/key-cert-match/"]').count()) === 1, 'match-tool link missing');
  return { error: text.slice(0, 80) };
});

await testCase('pem-to-pfx: EC key → friendly unsupported', async () => {
  await page.goto(`${BASE}/pem-to-pfx/`);
  await page.fill('#key-pem', fixtureText('pem/ec-key.pem'));
  await page.fill('#cert-pems', fixtureText('pem/ec-cert.pem'));
  await page.fill('#pfx-password', 'gate2pass');
  await page.click('#pfx-run');
  const text = await expectError(/EC|Ed25519/i);
  return { error: text.slice(0, 80) };
});

// -------------------------------------------------------- certificate decoder

await testCase('certificate-decoder: PEM cert → subject/SANs/signature + raw JSON', async () => {
  await page.goto(`${BASE}/certificate-decoder/`);
  await page.fill('#cert-input', fixtureText('pem/leaf-cert.pem'));
  await page.click('#cert-run');
  await expectResults();

  const summary = await page.locator('#cert-summary').innerText();
  assert(summary.includes('leaf.certkit.test'), 'subject missing');
  assert(summary.includes('sha256WithRSAEncryption'), 'signature algorithm missing');
  const sanText = await page.locator('#san-list').innerText();
  assert(sanText.includes('leaf.certkit.test'), 'SAN missing');

  await page.click('#view-json');
  const raw = await page.locator('#cert-json').innerText();
  const parsed = JSON.parse(raw);
  assert(parsed.type === 'SEQUENCE', 'raw JSON root should be a SEQUENCE');
  return { sanLines: sanText.split('\n').length, rawJsonBytes: raw.length };
});

await testCase('certificate-decoder: garbage input → error, no crash', async () => {
  await page.goto(`${BASE}/certificate-decoder/`);
  await page.fill('#cert-input', 'definitely not a certificate');
  await page.click('#cert-run');
  const text = await expectError(/./);
  return { error: text.slice(0, 80) };
});

// --------------------------------------------------------------- csr decoder

await testCase('csr-decoder: leaf CSR → CN, SANs, signature verified', async () => {
  await page.goto(`${BASE}/csr-decoder/`);
  await page.fill('#csr-input', fixtureText('pem/leaf.csr'));
  await page.click('#csr-run');
  await expectResults();

  const summary = await page.locator('#csr-summary').innerText();
  assert(summary.includes('leaf.certkit.test'), 'CN missing from summary');
  assert(summary.includes('sha256WithRSAEncryption'), 'signature algorithm missing');
  const badge = await page.locator('#sig-badge').innerText();
  assert(/verified/i.test(badge), 'signature badge: ' + badge);
  const sanText = await page.locator('#san-list').innerText();
  assert(sanText.includes('leaf.certkit.test'), 'SAN missing');
  return { badge, sans: sanText.split('\n').length };
});

await testCase('csr-decoder: garbage input → error', async () => {
  await page.goto(`${BASE}/csr-decoder/`);
  await page.fill('#csr-input', '-----BEGIN CERTIFICATE REQUEST-----\nzzzz\n-----END CERTIFICATE REQUEST-----');
  await page.click('#csr-run');
  const text = await expectError(/./);
  return { error: text.slice(0, 80) };
});

// ------------------------------------------------------------ key-cert-match

await testCase('key-cert-match: real pair → MATCH', async () => {
  await page.goto(`${BASE}/key-cert-match/`);
  await page.fill('#key-input', fixtureText('pem/leaf-key.pem'));
  await page.fill('#cert-input', fixtureText('pem/leaf-cert.pem'));
  await page.click('#match-run');
  await expectResults();
  const badge = await page.locator('#match-badge').innerText();
  assert(badge.startsWith('MATCH'), 'badge: ' + badge);
  const summary = await page.locator('#match-summary').innerText();
  assert(/Identical modulus/i.test(summary), 'modulus detail missing');
  assert(/Passed/i.test(summary), 'sign/verify detail missing');
  const report = await page.inputValue('#out-report');
  assert(/Result: MATCH/.test(report), 'report output missing MATCH');
  return { badge: badge.slice(0, 40) };
});

await testCase('key-cert-match: different pair → NO MATCH', async () => {
  await page.goto(`${BASE}/key-cert-match/`);
  await page.fill('#key-input', fixtureText('pem/leaf-key.pem'));
  await page.fill('#cert-input', fixtureText('pem/modern-cert.pem'));
  await page.click('#match-run');
  await expectResults();
  const badge = await page.locator('#match-badge').innerText();
  assert(badge.startsWith('NO MATCH'), 'badge: ' + badge);
  const advice = await page.locator('#match-advice').innerText();
  assert(/do not belong together/i.test(advice), 'advice missing');
  return { badge: badge.slice(0, 40) };
});

await testCase('key-cert-match: garbage key → error', async () => {
  await page.goto(`${BASE}/key-cert-match/`);
  await page.fill('#key-input', 'not a key');
  await page.fill('#cert-input', fixtureText('pem/leaf-cert.pem'));
  await page.click('#match-run');
  const text = await expectError(/./);
  return { error: text.slice(0, 80) };
});

// ---------------------------------------------------------------- chain-order

await testCase('chain-order: shuffled root/leaf/inter → ordered leaf→root', async () => {
  await page.goto(`${BASE}/chain-order/`);
  const shuffled = [
    fixtureText('pem/root-cert.pem'),
    fixtureText('pem/leaf-cert.pem'),
    fixtureText('pem/inter-cert.pem'),
  ].join('\n');
  await page.fill('#chain-input', shuffled);
  await page.click('#chain-run');
  await expectResults();

  const chain = await page.locator('#chain-list').innerText();
  const posLeaf = chain.indexOf('leaf.certkit.test');
  const posInter = chain.indexOf('inter.certkit.test');
  const posRoot = chain.indexOf('root.certkit.test');
  assert(posLeaf !== -1 && posInter !== -1 && posRoot !== -1, 'missing certs in output');
  assert(posLeaf < posInter && posInter < posRoot, 'order wrong: ' + JSON.stringify({ posLeaf, posInter, posRoot }));
  const links = await page.locator('#links-list').innerText();
  assert((links.match(/signature verified/g) || []).length === 2, 'expected 2 verified links: ' + links);
  assert(await page.locator('#missing-block').isHidden(), 'no missing issuer expected');
  const bundle = await page.inputValue('#out-chain');
  assert((bundle.match(/BEGIN CERTIFICATE/g) || []).length === 3, 'ordered bundle should hold 3 certs');
  const bundleCns = bundle
    .split(/(?=-----BEGIN CERTIFICATE-----)/)
    .filter((s) => s.includes('BEGIN CERTIFICATE'))
    .map((s) => forge.pki.certificateFromPem(s).subject.getField('CN').value);
  assert(
    JSON.stringify(bundleCns) === JSON.stringify(['leaf.certkit.test', 'inter.certkit.test', 'root.certkit.test']),
    'bundle order wrong: ' + bundleCns.join(',')
  );
  return { order: 'leaf → inter → root', links: 2, bundleBytes: bundle.length };
});

await testCase('chain-order: missing intermediate → reported + unlinked root', async () => {
  await page.goto(`${BASE}/chain-order/`);
  await page.fill('#chain-input', fixtureText('pem/leaf-cert.pem') + '\n' + fixtureText('pem/root-cert.pem'));
  await page.click('#chain-run');
  await expectResults();
  const missing = await page.locator('#missing-list').innerText();
  assert(missing.includes('inter.certkit.test'), 'missing issuer not reported: ' + missing);
  const unlinked = await page.locator('#unlinked-list').innerText();
  assert(unlinked.includes('root.certkit.test'), 'root should be listed as unlinked');
  return { missing: missing.slice(0, 80) };
});

// --------------------------------------------------------- der & jwk inspector

await testCase('der-jwk-inspector: DER certificate file → summary', async () => {
  await page.goto(`${BASE}/der-jwk-inspector/`);
  await page.setInputFiles('#der-file', fixtures('leaf-cert.der'));
  await page.click('#der-run');
  await page.waitForSelector('#der-results:not([hidden])', { timeout: 15000 });
  const summary = await page.locator('#der-summary').innerText();
  assert(summary.includes('leaf.certkit.test'), 'CN missing');
  assert(summary.includes('203.0.113.10'), 'IP SAN missing');
  const pem = await page.inputValue('#out-der-pem');
  assert(/BEGIN CERTIFICATE/.test(pem), 'PEM output missing');
  return { summaryLines: summary.split('\n').length };
});

await testCase('der-jwk-inspector: JWK set → 2 keys with kid/alg/use', async () => {
  await page.goto(`${BASE}/der-jwk-inspector/`);
  await page.fill('#jwk-input', fixtureText('jwk/jwks.json'));
  await page.click('#jwk-run');
  await page.waitForSelector('#jwk-results:not([hidden])', { timeout: 15000 });
  const summary = await page.locator('#jwk-summary').innerText();
  assert(summary.includes('JWK Set'), 'kind missing');
  assert(summary.includes('2'), 'key count missing');
  const rows = await page.locator('#jwk-table tbody tr').count();
  assert(rows === 2, 'expected 2 table rows, got ' + rows);
  const table = await page.locator('#jwk-table').innerText();
  assert(table.includes('certkit-leaf-2026-09'), 'kid missing');
  assert(table.includes('RS256'), 'alg missing');
  assert(table.includes('sig'), 'use missing');
  assert(table.includes('EC'), 'EC member missing');
  const note = await page.locator('#jwk-results').innerText();
  assert(/no signature verification/i.test(note), 'no-verification note missing');
  const report = JSON.parse(await page.inputValue('#out-jwk-json'));
  assert(report.kind === 'JWK Set' && report.keyCount === 2, 'JSON report wrong');
  return { rows, reportKeys: report.keys.length };
});

await testCase('der-jwk-inspector: invalid JWK JSON → error', async () => {
  await page.goto(`${BASE}/der-jwk-inspector/`);
  await page.fill('#jwk-input', '{"nope": true}');
  await page.click('#jwk-run');
  const text = await expectError(/JWK/i);
  return { error: text.slice(0, 80) };
});

// ---------- summary ----------

const passed = results.filter((r) => r.ok).length;
const summary = {
  engine: 'chromium via playwright-core',
  baseUrl: BASE,
  builtAt: new Date().toISOString(),
  total: results.length,
  passed,
  failed: results.length - passed,
  cases: results,
};
writeFileSync(join(root, 'tests', 'out', 'mvp-results.json'), JSON.stringify(summary, null, 2));

await browser.close();
await stopServer(server);

console.log(`\n${passed}/${results.length} cases passed — wrote tests/out/mvp-results.json`);
if (passed !== results.length) process.exit(1);
