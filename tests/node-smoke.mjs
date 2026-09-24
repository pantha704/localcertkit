/**
 * Node smoke test — loads the SAME lib/certkit.js module used by the browser page,
 * parses every fixture, prints a machine-readable table.
 * Evidence channel #1 (fast iteration); browser test is the real proof.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const CertKit = require('../lib/certkit.js');

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const fixtures = [
  { file: 'modern-aes256.p12', password: 'modernpass', expect: 'pass' },
  { file: 'legacy-3des.p12', password: 'legacypass', expect: 'pass?' },
  { file: 'legacy-rc2-40.p12', password: 'legacypass', expect: 'pass?' },
  { file: 'nopass.p12', password: null, expect: 'pass?' },
  { file: 'nomac.p12', password: 'nomacpass', expect: 'pass?' },
  { file: 'chain-aes256.p12', password: 'chainpass', expect: 'pass' },
  { file: 'modern-aes256-rsa4096.p12', password: 'bigpass', expect: 'pass' },
  { file: 'ec-p256-aes256.p12', password: 'ecpass', expect: 'fail?' },
  { file: 'modern-aes256.p12', password: 'WRONG', expect: 'fail' },
];

const rows = [];
for (const f of fixtures) {
  const bytes = new Uint8Array(readFileSync(join(root, 'fixtures', f.file)));
  const t0 = performance.now();
  let out;
  try {
    const r = CertKit.parsePfx(bytes, f.password);
    const ms = performance.now() - t0;
    out = {
      file: f.file,
      password: f.password === null ? '(empty)' : f.password,
      ok: true,
      wallMs: +ms.toFixed(1),
      certs: r.certs.length,
      keyType: r.privateKeyType,
      match: r.keyMatch ? r.keyMatch.match : null,
      modulusEqual: r.keyMatch ? r.keyMatch.modulusEqual : null,
      signVerify: r.keyMatch ? r.keyMatch.signVerify : null,
      subjectCN: r.certs[0] ? (r.certs[0].subject.find((a) => a.short === 'CN') || {}).value : null,
      issuerCN: r.certs[0] ? (r.certs[0].issuer.find((a) => a.short === 'CN') || {}).value : null,
      sans: r.certs[0] ? r.certs[0].san.map((s) => `${s.type}:${s.value}`).join(',') : null,
      serial: r.certs[0] ? r.certs[0].serialNumber : null,
      pemKeyLen: r.pems.privateKey ? r.pems.privateKey.length : 0,
      pemCertsLen: r.pems.certificates.length,
      bundleLen: r.pems.bundle.length,
      oids: r.rawOids.map((o) => o.name).join('|'),
    };
  } catch (e) {
    out = { file: f.file, password: f.password === null ? '(empty)' : f.password, ok: false, error: e.message, wallMs: +(performance.now() - t0).toFixed(1) };
  }
  out.expect = f.expect;
  rows.push(out);
}

for (const r of rows) {
  console.log(JSON.stringify(r));
}
mkdirSync(join(root, 'tests', 'out'), { recursive: true });
writeFileSync(join(root, 'tests', 'out', 'node-results.json'), JSON.stringify(rows, null, 2));

// negative control: key from one fixture vs cert from another must NOT match
{
  const a = CertKit.parsePfx(new Uint8Array(readFileSync(join(root, 'fixtures', 'modern-aes256.p12'))), 'modernpass');
  const b = CertKit.parsePfx(new Uint8Array(readFileSync(join(root, 'fixtures', 'chain-aes256.p12'))), 'chainpass');
  const cross = CertKit.keyMatchesCert(a.raw.privateKey, b.raw.certs[0]);
  const row = {
    file: 'cross-match negative control',
    password: '(a.key vs b.cert)',
    ok: true,
    expect: 'no-match',
    match: cross.match,
    modulusEqual: cross.modulusEqual,
    signVerify: cross.signVerify,
  };
  rows.push(row);
  console.log(JSON.stringify(row));
  writeFileSync(join(root, 'tests', 'out', 'node-results.json'), JSON.stringify(rows, null, 2));
}
console.log('\nwrote tests/out/node-results.json');
