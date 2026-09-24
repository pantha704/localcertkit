/**
 * Copy the single-source client library + vendored forge into the static site
 * before dev/build. Keeps lib/certkit.js as the only copy of the code (the same
 * file the Node tests require), avoids drift, and keeps the site fully static.
 */
import { copyFileSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const site = join(root, 'site');

mkdirSync(join(site, 'public', 'vendor'), { recursive: true });
mkdirSync(join(site, 'public', 'lib'), { recursive: true });

const pairs = [
  [join(root, 'vendor', 'forge.min.js'), join(site, 'public', 'vendor', 'forge.min.js')],
  [join(root, 'lib', 'certkit.js'), join(site, 'public', 'lib', 'certkit.js')],
];

for (const [from, to] of pairs) {
  copyFileSync(from, to);
  const size = statSync(to).size;
  if (size < 1000) throw new Error(`copy looks wrong (${size} bytes): ${to}`);
  console.log(`[certkit-site] ${from.replace(root + '/', '')} → site/public/… (${size} bytes)`);
}
