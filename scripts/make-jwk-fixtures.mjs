/**
 * Generate JWK / JWK-set fixtures for the Gate-1 DER/JWK inspector.
 * Uses Node's built-in crypto JWK export (RFC 7517 output).
 *
 * Fixtures (all throwaway test material, same leaf key as the cert fixtures):
 *   fixtures/jwk/leaf-pub.jwk.json   RSA public key, with kid/alg/use
 *   fixtures/jwk/leaf-key.jwk.json   RSA private key (contains "d") — warning test case
 *   fixtures/jwk/jwks.json           JWK set: RSA public + a generated EC P-256 public key
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createPublicKey, createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'fixtures', 'jwk');
mkdirSync(outDir, { recursive: true });

const keyPem = readFileSync(join(root, 'fixtures', 'pem', 'leaf-key.pem'), 'utf8');
const pubJwk = createPublicKey(keyPem).export({ format: 'jwk' });
const privJwk = createPrivateKey(keyPem).export({ format: 'jwk' });

const kid = 'certkit-leaf-2026-09';
const pub = { ...pubJwk, kid, alg: 'RS256', use: 'sig' };
const priv = { ...privJwk, kid, alg: 'RS256', use: 'sig' };

// A second, unrelated EC key so the JWK-set view shows a non-RSA member
// (JWK inspection is pure JSON and works for EC even though X.509/PKCS#12 v1 is RSA-only).
const { publicKey: ecPub } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ecJwk = ecPub.export({ format: 'jwk' });
const ec = { ...ecJwk, kid: 'certkit-ec-demo', alg: 'ES256', use: 'sig' };

writeFileSync(join(outDir, 'leaf-pub.jwk.json'), JSON.stringify(pub, null, 2) + '\n');
writeFileSync(join(outDir, 'leaf-key.jwk.json'), JSON.stringify(priv, null, 2) + '\n');
writeFileSync(
  join(outDir, 'jwks.json'),
  JSON.stringify({ keys: [pub, ec] }, null, 2) + '\n'
);

console.log('wrote fixtures/jwk/{leaf-pub.jwk.json,leaf-key.jwk.json,jwks.json}');
