// Post-build: list every built file with its SHA-256 (publish this in the GitHub Release so anyone can
// compare against what the live site serves), and stamp the Service Worker with the build version.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const dist = process.argv[2] ?? 'dist';
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const files = walk(dist)
  .map((p) => relative(dist, p).split(sep).join('/'))
  .filter((p) => p !== 'asset-manifest.json' && p !== 'sw.js')
  .sort()
  .map((path) => ({ path, sha256: createHash('sha256').update(readFileSync(join(dist, path))).digest('hex') }));
const version = createHash('sha256').update(JSON.stringify(files)).digest('hex').slice(0, 16);
const swPath = join(dist, 'sw.js');
writeFileSync(swPath, readFileSync(swPath, 'utf8').replace('__BUILD_VERSION__', version));
const sw = { path: 'sw.js', sha256: createHash('sha256').update(readFileSync(swPath)).digest('hex') };
writeFileSync(join(dist, 'asset-manifest.json'), JSON.stringify({ version, files: files.filter((f) => f.path.startsWith('assets/') || f.path === 'index.html').filter((f) => f.path !== 'index.html'), all: [...files, sw] }, null, 2));
console.log(`asset manifest: ${files.length + 1} files, version ${version}`);
