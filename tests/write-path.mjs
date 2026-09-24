/**
 * Write-path evidence: PEM (private key + chain) -> PKCS#12 using forge, then
 * verify OpenSSL can read the result back and the extracted key matches the cert.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const forge = require('node-forge');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'tests', 'out');
mkdirSync(out, { recursive: true });

const password = 'forgepass';
const key = forge.pki.privateKeyFromPem(readFileSync(join(root, 'fixtures/pem/leaf-key.pem'), 'utf8'));
const certs = [
  forge.pki.certificateFromPem(readFileSync(join(root, 'fixtures/pem/leaf-cert.pem'), 'utf8')),
  forge.pki.certificateFromPem(readFileSync(join(root, 'fixtures/pem/inter-cert.pem'), 'utf8')),
];

const p12Path = join(out, 'forge-write.p12');
const asn1 = forge.pkcs12.toPkcs12Asn1(key, certs, password, { algorithm: 'aes256', friendlyName: 'forge-made' });
writeFileSync(p12Path, Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary'));

const report = { file: p12Path };

// 1. forge reads its own output back
const reread = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.createBuffer(readFileSync(p12Path).toString('binary'))), password);
report.forgeReread = {
  keyBags: reread.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag].length,
  certBags: reread.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag].length,
};

// 2. OpenSSL reads it; algorithms + counts (openssl writes -info text to stderr)
const info = spawnSync('openssl', ['pkcs12', '-in', p12Path, '-passin', 'pass:' + password, '-info', '-noout'], { encoding: 'utf8' });
report.opensslInfo = ((info.stdout || '') + (info.stderr || ''))
  .split('\n').filter((l) => /MAC|Encrypted|Keybag|PKCS7|Certificate/.test(l)).join('\n');

// 3. OpenSSL extracts; key modulus must equal leaf cert modulus
const extractPath = join(out, 'forge-extract.pem');
execFileSync('openssl', ['pkcs12', '-in', p12Path, '-passin', 'pass:' + password, '-nodes', '-out', extractPath], { stdio: 'pipe' });
const md5 = (buf) => execFileSync('md5sum', { input: buf, encoding: 'utf8' }).split(' ')[0];
const keyMod = execFileSync('openssl', ['rsa', '-in', extractPath, '-noout', '-modulus'], { encoding: 'utf8' });
const certMod = execFileSync('openssl', ['x509', '-in', extractPath, '-noout', '-modulus'], { encoding: 'utf8' });
const origKeyMod = execFileSync('openssl', ['rsa', '-in', join(root, 'fixtures/pem/leaf-key.pem'), '-noout', '-modulus'], { encoding: 'utf8' });
report.opensslRoundTrip = {
  extractedCerts: (readFileSync(extractPath, 'utf8').match(/BEGIN CERTIFICATE/g) || []).length,
  keyModulusMd5: md5(keyMod),
  certModulusMd5: md5(certMod),
  originalKeyModulusMd5: md5(origKeyMod),
  keyMatchesCert: md5(keyMod) === md5(certMod),
  keyMatchesOriginal: md5(keyMod) === md5(origKeyMod),
};

console.log(JSON.stringify(report, null, 2));
writeFileSync(join(out, 'write-path-results.json'), JSON.stringify(report, null, 2));
