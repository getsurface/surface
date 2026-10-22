// Builds a single-file preview of the site (CSS and JS inlined) for sharing
// a static look at the design. The preview has no backend, so live checks
// show the "scanner isn't reachable" message by design.
//
// Usage: node scripts/build-preview.mjs <output.html> [title]
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = process.argv[2];
const title = process.argv[3] || 'Surface Check';
if (!out) {
  console.error('Usage: node scripts/build-preview.mjs <output.html> [title]');
  process.exit(1);
}

const html = await readFile(join(root, 'index.html'), 'utf8');
const css = await readFile(join(root, 'assets/app.css'), 'utf8');
const js = await readFile(join(root, 'assets/app.js'), 'utf8');

const head = (html.match(/<head[^>]*>([\s\S]*?)<\/head>/i) || [, ''])[1];
const fontLinks = (head.match(/<link[^>]+fonts\.(googleapis|gstatic)\.com[^>]*>/gi) || []).join('\n');

let body = (html.match(/<body[^>]*>([\s\S]*?)<\/body>/i) || [, ''])[1];
body = body.replace(/<script[^>]*src=["'][^"']*app\.js["'][^>]*>\s*<\/script>/i, '');

// Inline scripts must not contain a literal closing script tag.
const safeJs = js.replace(/<\/script/gi, '<\\/script');

const page = `<title>${title}</title>
<meta name="claude:viewport-fit-sides" content="cover">
${fontLinks}
<style>
${css}
</style>
${body.trim()}
<script>
${safeJs}
</script>
`;

await writeFile(out, page);
console.log(`Preview written to ${out} (${(page.length / 1024).toFixed(1)} KB)`);
