/**
 * Gate-1 lib evidence — the SAME lib/certkit.js the site loads, exercised in Node
 * against the spike fixtures. Fast channel; the browser harness is the real proof.
 *
 * Covers: certificate decode (PEM + DER), CSR decode, key↔cert match, chain
 * ordering (shuffled / missing intermediate / duplicates), JWK inspection,
 * PEM → PKCS#12 write, and the EC-unsupported error paths.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const CertKit = require('../lib/certkit.js');
const forge = require('node-forge');

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fx = (p) => readFileSync(join(root, 'fixtures', p));
const fxt = (p) => fx(p).toString('utf8');

const results = [];
function check(name, fn) {
  const t0 = performance.now();
  try {
    const detail = fn() || {};
    results.push({ name, ok: true, ms: +(performance.now() - t0).toFixed(1), ...detail });
    console.log(`PASS  ${name}  ${JSON.stringify(detail).slice(0, 160)}`);
  } catch (e) {
    results.push({ name, ok: false, ms: +(performance.now() - t0).toFixed(1), error: e.message, code: e.code });
    console.log(`FAIL  ${name}  ${e.message}`);
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg || 'assertion failed');
};
const throwsCode = (fn, code) => {
  try {
    fn();
  } catch (e) {
    if (code) assert(e.code === code, `expected code ${code}, got "${e.code}" (${e.message})`);
    return e.message;
  }
  throw new Error('expected an error, none thrown');
};

// ---------- certificate decode ----------
let leafInfo;
check('decode cert from PEM', () => {
  const d = CertKit.decodeCertificate(fxt('pem/leaf-cert.pem'));
  leafInfo = d.info;
  const cn = d.info.subject.find((a) => a.short === 'CN').value;
  assert(cn === 'leaf.certkit.test', 'CN mismatch: ' + cn);
  assert(d.info.san.some((s) => s.type === 'DNS' && s.value === 'leaf.certkit.test'), 'DNS SAN missing');
  assert(d.info.san.some((s) => s.type === 'IP' && s.value === '203.0.113.10'), 'IP SAN not formatted: ' + JSON.stringify(d.info.san));
  assert(d.info.signatureAlgorithm.name === 'sha256WithRSAEncryption', 'sig alg: ' + JSON.stringify(d.info.signatureAlgorithm));
  assert(d.info.isCA === false, 'leaf must not be CA');
  assert(d.info.rsaBits === 2048, 'bits: ' + d.info.rsaBits);
  assert(d.info.asn1 && d.info.asn1.type === 'SEQUENCE', 'ASN.1 json missing');
  return { cn, sans: d.info.san.length, sig: d.info.signatureAlgorithm.name };
});

check('decode cert from DER bytes', () => {
  const d = CertKit.decodeCertificate(new Uint8Array(fx('leaf-cert.der')));
  const cn = d.info.subject.find((a) => a.short === 'CN').value;
  assert(cn === 'leaf.certkit.test', 'CN mismatch');
  assert(d.der.length === fx('leaf-cert.der').length, 're-encoded DER length differs');
  assert(Buffer.from(d.der).equals(fx('leaf-cert.der')), 're-encoded DER bytes differ from fixture');
  return { cn, derBytes: d.der.length };
});

check('EC certificate → friendly EC_UNSUPPORTED', () => {
  const msg = throwsCode(() => CertKit.decodeCertificate(fxt('pem/ec-cert.pem')), 'EC_UNSUPPORTED');
  assert(/EC\/Ed25519|EC or Ed25519|roadmap/i.test(msg), 'message not friendly: ' + msg);
  return { message: msg.slice(0, 80) };
});

check('garbage certificate input → clear error', () => {
  const msg = throwsCode(() => CertKit.decodeCertificate('not a certificate'), '');
  return { message: msg.slice(0, 90) };
});

// ---------- CSR decode ----------
check('decode CSR (SANs + signature verify)', () => {
  const d = CertKit.decodeCsr(fxt('pem/leaf.csr'));
  const cn = d.info.subject.find((a) => a.short === 'CN').value;
  assert(cn === 'leaf.certkit.test', 'CN: ' + cn);
  assert(d.info.sans.some((s) => s.type === 'DNS' && s.value === 'leaf.certkit.test'), 'CSR SAN missing: ' + JSON.stringify(d.info.sans));
  assert(d.info.keyBits === 2048, 'key bits');
  assert(d.info.signatureValid === true, 'CSR signature must verify');
  assert(d.info.signatureAlgorithm.name === 'sha256WithRSAEncryption', 'sig alg');
  return { cn, sans: d.info.sans.map((s) => s.type + ':' + s.value).join(','), sigValid: d.info.signatureValid };
});

check('garbage CSR input → clear error', () => {
  const msg = throwsCode(() => CertKit.decodeCsr('-----BEGIN CERTIFICATE REQUEST-----\nzzz\n-----END CERTIFICATE REQUEST-----'), '');
  return { message: msg.slice(0, 90) };
});

// ---------- key ↔ cert match ----------
check('key matches own certificate', () => {
  const r = CertKit.keyMatchReport(fxt('pem/leaf-key.pem'), fxt('pem/leaf-cert.pem'));
  assert(r.match === true && r.modulusEqual === true && r.signVerify === true, JSON.stringify(r));
  return { match: r.match, signVerify: r.signVerify };
});

check('different key → NO match (negative control)', () => {
  const r = CertKit.keyMatchReport(fxt('pem/modern-key.pem'), fxt('pem/leaf-cert.pem'));
  assert(r.match === false && r.modulusEqual === false, JSON.stringify(r));
  assert(r.signVerify !== true, 'sign/verify must not pass for a different key');
  return { match: r.match, modulusEqual: r.modulusEqual, signVerify: r.signVerify, err: r.signVerifyError };
});

check('EC key → friendly EC_UNSUPPORTED', () => {
  const msg = throwsCode(() => CertKit.keyMatchReport(fxt('pem/ec-key.pem'), fxt('pem/ec-cert.pem')), 'EC_UNSUPPORTED');
  return { message: msg.slice(0, 80) };
});

// ---------- chain ordering ----------
check('chain order: shuffled root/leaf/inter → leaf,inter,root', () => {
  const inputs = [fxt('pem/root-cert.pem'), fxt('pem/leaf-cert.pem'), fxt('pem/inter-cert.pem')];
  const r = CertKit.orderChain(inputs);
  const order = r.ordered.map((o) => o.entry.subjectCN);
  assert(JSON.stringify(order) === JSON.stringify(['leaf.certkit.test', 'inter.certkit.test', 'root.certkit.test']), 'order: ' + order);
  assert(r.missing.length === 0, 'no missing links expected');
  assert(r.unlinked.length === 0, 'nothing should be unlinked');
  assert(r.links.length === 2 && r.links.every((l) => l.signatureValid === true), 'links must verify');
  assert(r.allValid === true, 'allValid');
  return { order: order.join(' → '), links: r.links.length, sigValid: true };
});

check('chain order: missing intermediate reported', () => {
  const r = CertKit.orderChain([fxt('pem/leaf-cert.pem'), fxt('pem/root-cert.pem')]);
  assert(r.ordered[0].entry.subjectCN === 'leaf.certkit.test', 'leaf must be first');
  assert(r.missing.length === 1, 'one missing link expected: ' + JSON.stringify(r.missing));
  assert(r.missing[0].issuerCN === 'inter.certkit.test', 'missing issuer: ' + r.missing[0].issuerCN);
  assert(r.unlinked.length === 1 && r.unlinked[0].entry.subjectCN === 'root.certkit.test', 'root should be unlinked');
  assert(r.allValid === false, 'allValid must be false');
  return { missing: r.missing[0].issuerCN, unlinked: r.unlinked[0].entry.subjectCN };
});

check('chain order: duplicates counted, chain still ordered', () => {
  const inputs = [fxt('pem/leaf-cert.pem'), fxt('pem/inter-cert.pem'), fxt('pem/leaf-cert.pem'), fxt('pem/root-cert.pem')];
  const r = CertKit.orderChain(inputs);
  assert(r.duplicates === 1, 'duplicates: ' + r.duplicates);
  const order = r.ordered.map((o) => o.entry.subjectCN);
  assert(JSON.stringify(order) === JSON.stringify(['leaf.certkit.test', 'inter.certkit.test', 'root.certkit.test']), 'order');
  return { duplicates: r.duplicates, chain: r.count };
});

check('splitPemCertificates splits chain.pem', () => {
  const parts = CertKit.splitPemCertificates(fxt('pem/chain.pem'));
  assert(parts.length === 2, 'expected 2 certs, got ' + parts.length);
  return { count: parts.length };
});

// ---------- JWK inspection ----------
check('JWK set inspect (RSA + EC members)', () => {
  const r = CertKit.inspectJwk(fxt('jwk/jwks.json'));
  assert(r.kind === 'JWK Set' && r.keyCount === 2, JSON.stringify({ kind: r.kind, keyCount: r.keyCount }));
  const rsa = r.keys[0];
  const ec = r.keys[1];
  assert(rsa.kty === 'RSA' && rsa.bits === 2048, 'RSA member: ' + JSON.stringify(rsa));
  assert(rsa.kid === 'certkit-leaf-2026-09' && rsa.alg === 'RS256' && rsa.use === 'sig', 'kid/alg/use');
  assert(ec.kty === 'EC' && ec.crv === 'P-256' && ec.bits === 256, 'EC member: ' + JSON.stringify(ec));
  return { kind: r.kind, keys: r.keys.map((k) => k.kty).join('+') };
});

check('private JWK → private-material warning', () => {
  const r = CertKit.inspectJwk(fxt('jwk/leaf-key.jwk.json'));
  assert(r.keyCount === 1 && r.keys[0].hasPrivateMaterial === true, 'should flag private material');
  assert(r.warnings.some((w) => /PRIVATE/i.test(w)), 'warning text');
  return { warnings: r.warnings.length };
});

check('invalid JWK JSON → clear error', () => {
  const msg = throwsCode(() => CertKit.inspectJwk('{"hello": 1}'), '');
  return { message: msg.slice(0, 90) };
});

// ---------- PEM → PKCS#12 ----------
check('pemToPfx produces a valid PKCS#12 (forge re-read)', () => {
  const r = CertKit.pemToPfx({
    keyPem: fxt('pem/leaf-key.pem'),
    certPems: [fxt('pem/leaf-cert.pem'), fxt('pem/inter-cert.pem')],
    password: 'gate1pass',
    friendlyName: 'certkit-gate1',
  });
  assert(r.bytes[0] === 0x30, 'PFX should start with SEQUENCE tag (0x30)');
  const reread = forge.pkcs12.pkcs12FromAsn1(
    forge.asn1.fromDer(forge.util.createBuffer(CertKit.bytesToBinaryString(r.bytes))),
    'gate1pass'
  );
  const keyBags = reread.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
  const certBags = reread.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
  assert(keyBags.length === 1, 'key bags: ' + keyBags.length);
  assert(certBags.length === 2, 'cert bags: ' + certBags.length);
  const match = CertKit.keyMatchesCert(keyBags[0].key, certBags[0].cert);
  assert(match.match === true, 'round-tripped key must match cert');
  assert(r.base64.length > 1000, 'base64 output');
  return { pfxBytes: r.bytes.length, certBags: certBags.length, keyMatch: match.match };
});

check('pemToPfx refuses mismatched key/cert', () => {
  const msg = throwsCode(
    () => CertKit.pemToPfx({ keyPem: fxt('pem/modern-key.pem'), certPems: [fxt('pem/leaf-cert.pem')], password: 'x' }),
    'KEY_MISMATCH'
  );
  return { message: msg.slice(0, 80) };
});

check('pemToPfx EC key → friendly EC_UNSUPPORTED', () => {
  const msg = throwsCode(
    () => CertKit.pemToPfx({ keyPem: fxt('pem/ec-key.pem'), certPems: [fxt('pem/ec-cert.pem')], password: 'x' }),
    'EC_UNSUPPORTED'
  );
  return { message: msg.slice(0, 80) };
});

// ---------- summary ----------
mkdirSync(join(root, 'tests', 'out'), { recursive: true });
const passed = results.filter((r) => r.ok).length;
const summary = { total: results.length, passed, failed: results.length - passed, results };
writeFileSync(join(root, 'tests', 'out', 'lib-gate1-results.json'), JSON.stringify(summary, null, 2));
console.log(`\n${passed}/${results.length} checks passed — wrote tests/out/lib-gate1-results.json`);
if (passed !== results.length) process.exit(1);
