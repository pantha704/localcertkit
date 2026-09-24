/**
 * Browser evidence — runs the actual static page (index.html + vendor/forge.min.js
 * + lib/certkit.js) in headless Chromium, drives the UI exactly like a user would
 * (file picker + password + Parse button), and records what the page computed.
 *
 * Also round-trips the exported PEM back through node-forge in Node to prove the
 * exports are valid and the key/cert match is real.
 */
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const forge = require('node-forge');

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const CHROME =
  process.env.CHROME_PATH ||
  `${process.env.HOME}/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome`;
if (!existsSync(CHROME)) throw new Error('chromium not found at ' + CHROME);

const fixtures = [
  { file: 'modern-aes256.p12', password: 'modernpass', expect: 'pass', runs: 1 },
  { file: 'legacy-3des.p12', password: 'legacypass', expect: 'pass', runs: 1 },
  { file: 'legacy-rc2-40.p12', password: 'legacypass', expect: 'pass', runs: 1 },
  { file: 'nopass.p12', password: '', expect: 'pass', runs: 1 },
  { file: 'nomac.p12', password: 'nomacpass', expect: 'pass', runs: 1 },
  { file: 'chain-aes256.p12', password: 'chainpass', expect: 'pass', runs: 1 },
  { file: 'modern-aes256-rsa4096.p12', password: 'bigpass', expect: 'pass', runs: 5 },
  { file: 'ec-p256-aes256.p12', password: 'ecpass', expect: 'fail', runs: 1 },
  { file: 'modern-aes256.p12', password: 'WRONG', expect: 'fail', runs: 1 },
];

const summarizeInPage = () => {
  const r = window.__certkit_result;
  if (!r) return null;
  const c0 = r.certs && r.certs[0];
  const findCN = (attrs) => ((attrs || []).find((a) => a.short === 'CN') || {}).value || null;
  return {
    ok: r.ok,
    error: r.error || null,
    fileBytes: r.fileBytes,
    wallMs: r.wallMs,
    certs: r.certs ? r.certs.length : 0,
    keyType: r.privateKeyType || null,
    match: r.keyMatch ? r.keyMatch.match : null,
    modulusEqual: r.keyMatch ? r.keyMatch.modulusEqual : null,
    signVerify: r.keyMatch ? r.keyMatch.signVerify : null,
    subjectCN: c0 ? findCN(c0.subject) : null,
    issuerCN: c0 ? findCN(c0.issuer) : null,
    sans: c0 ? c0.san.map((s) => s.type + ':' + s.value).join(',') : null,
    serial: c0 ? c0.serialNumber : null,
    fingerprint: c0 ? c0.sha256Fingerprint : null,
    oids: r.rawOids ? r.rawOids.map((o) => o.name).join(',') : '',
    pemKeyLen: r.pems && r.pems.privateKey ? r.pems.privateKey.length : 0,
    pemCertsLen: r.pems ? r.pems.certificates.length : 0,
    bundleLen: r.pems ? r.pems.bundle.length : 0,
    keyTextarea: !!document.querySelector('#pem-key'),
    certTextareas: document.querySelectorAll('textarea[id^="pem-cert"]').length,
    renderedSummary: (document.querySelector('#results') || {}).innerText
      ? document.querySelector('#results').innerText.split('\n').slice(0, 22).join('\n')
      : '',
  };
};

const pageUrl = pathToFileURL(join(root, 'index.html')).href;
const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
const context = await browser.newContext();
const page = await context.newPage();

const consoleErrors = [];
const pageErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', (e) => pageErrors.push(String(e)));

const results = { engine: 'chromium-1243 headless', page: pageUrl, cases: [] };

for (const fx of fixtures) {
  const caseRow = { file: fx.file, password: fx.password === '' ? '(empty)' : fx.password, expect: fx.expect, runs: [] };
  for (let i = 0; i < fx.runs; i++) {
    await page.goto(pageUrl);
    await page.setInputFiles('#pfx', join(root, 'fixtures', fx.file));
    await page.fill('#pw', fx.password);
    await page.click('#parse');
    await page.waitForFunction(() => window.__certkit_state === 'done', null, { timeout: 30000 });
    const s = await page.evaluate(summarizeInPage);
    caseRow.runs.push(s);
  }
  const last = caseRow.runs[caseRow.runs.length - 1];
  caseRow.ok = last.ok;
  caseRow.error = last.error;
  caseRow.wallMs = last.wallMs;
  caseRow.match = last.match;
  caseRow.pemKeyLen = last.pemKeyLen;
  caseRow.pemCertsLen = last.pemCertsLen;
  caseRow.bundleLen = last.bundleLen;
  caseRow.subjectCN = last.subjectCN;
  caseRow.issuerCN = last.issuerCN;
  caseRow.sans = last.sans;

  if (caseRow.ok && caseRow.pemKeyLen > 0) {
    // PEM round-trip in Node: parse exported PEM and re-verify key/cert match
    const pems = await page.evaluate(() => ({
      key: document.querySelector('#pem-key').value,
      certs: document.querySelector('#pem-certs') ? document.querySelector('#pem-certs').value : '',
      bundle: document.querySelector('#pem-bundle') ? document.querySelector('#pem-bundle').value : '',
    }));
    try {
      const priv = forge.pki.privateKeyFromPem(pems.key);
      const certObjs = pems.certs
        .split(/(?=-----BEGIN CERTIFICATE-----)/)
        .filter((s) => s.includes('BEGIN CERTIFICATE'))
        .map((s) => forge.pki.certificateFromPem(s));
      const rt = CertKitKeyMatch(priv, certObjs[0]);
      caseRow.pemRoundTrip = {
        privParsed: !!priv.n,
        certsParsed: certObjs.length,
        keyMatchInNode: rt.match,
        certChainLinked: certObjs.length > 1 ? certObjs[1].subject.getField('CN').value === certObjs[0].issuer.getField('CN').value : null,
      };
    } catch (e) {
      caseRow.pemRoundTrip = { error: e.message };
    }
  }
  results.cases.push(caseRow);
  console.log(JSON.stringify(caseRow));
}

// in-page UI timing for the 4 KB file: 10 parse cycles driven through the page
// (parse-only ms from lib + wall ms including DOM render)
await page.goto(pageUrl);
await page.setInputFiles('#pfx', join(root, 'fixtures', 'modern-aes256-rsa4096.p12'));
await page.fill('#pw', 'bigpass');
const perfTimes = [];
const perfParseOnly = [];
const memBefore = await page.evaluate(() =>
  performance.memory ? +(performance.memory.usedJSHeapSize / 1048576).toFixed(1) : null
);
for (let i = 0; i < 10; i++) {
  const t = Date.now();
  await page.click('#parse');
  await page.waitForFunction(() => window.__certkit_state === 'done');
  perfTimes.push(Date.now() - t);
  const em = await page.evaluate(() => window.__certkit_result.elapsedMs);
  perfParseOnly.push(em);
  await page.evaluate(() => { window.__certkit_state = 'idle'; });
}
const mem = await page.evaluate(() =>
  performance.memory
    ? { usedJSHeapMB: +(performance.memory.usedJSHeapSize / 1048576).toFixed(1), totalJSHeapMB: +(performance.memory.totalJSHeapSize / 1048576).toFixed(1) }
    : null
);
const perf = { fileBytes: readFileSync(join(root, 'fixtures', 'modern-aes256-rsa4096.p12')).length, wallMs: perfTimes, parseOnlyMs: perfParseOnly, mem, memBeforeMB: memBefore };
results.perf4kb = perf;
console.log('perf 4KB:', JSON.stringify(perf));

results.consoleErrors = consoleErrors;
results.pageErrors = pageErrors;
mkdirSync(join(root, 'tests', 'out'), { recursive: true });
writeFileSync(join(root, 'tests', 'out', 'browser-results.json'), JSON.stringify(results, null, 2));
await browser.close();

function CertKitKeyMatch(privateKey, cert) {
  const pub = cert.publicKey;
  const modulusEqual = privateKey.n.compareTo(pub.n) === 0 && (privateKey.e.compareTo ? privateKey.e.compareTo(pub.e) === 0 : privateKey.e === pub.e);
  const md1 = forge.md.sha256.create();
  md1.update('certkit-key-match-test');
  const sig = privateKey.sign(md1);
  const md2 = forge.md.sha256.create();
  md2.update('certkit-key-match-test');
  const signVerify = pub.verify(md2.digest().bytes(), sig);
  return { match: modulusEqual && signVerify !== false, modulusEqual, signVerify };
}

console.log('\nconsoleErrors:', consoleErrors.length, 'pageErrors:', pageErrors.length);
console.log('wrote tests/out/browser-results.json');
