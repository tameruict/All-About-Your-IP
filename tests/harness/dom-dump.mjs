// Dump the outerHTML + ancestor context of text nodes containing a substring.
// UI Automation only exposes Name, which loses where the text lives and what it
// is attached to. Reading the DOM through WebView2's remote debugging port gives
// the actual element, its attributes and its parent.

import http from 'node:http';

const PORT = Number(process.argv[2] || 9222);
const NEEDLE = process.argv[3] || 'lỗi';

function get(path) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: PORT, path, timeout: 5000 }, (res) => {
      let d = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve(d));
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
  });
}

const targets = JSON.parse(await get('/json/list'));
const page = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
if (!page) {
  console.log('no debuggable page target found; targets:', targets.map((t) => t.type).join(','));
  process.exit(1);
}
console.log(`page: ${page.title} | ${page.url}`);

const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();

function send(method, params) {
  return new Promise((resolve, reject) => {
    const msgId = ++id;
    pending.set(msgId, { resolve, reject });
    ws.send(JSON.stringify({ id: msgId, method, params }));
  });
}

ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { resolve, reject } = pending.get(m.id);
    pending.delete(m.id);
    if (m.error) reject(new Error(m.error.message));
    else resolve(m.result);
  }
});

await new Promise((r) => ws.addEventListener('open', r));

const expression = `
(() => {
  const needle = ${JSON.stringify(NEEDLE)};
  const out = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const t = (n.nodeValue || '').trim();
    if (!t.toLowerCase().includes(needle.toLowerCase())) continue;
    const el = n.parentElement;
    if (!el) continue;
    const chain = [];
    let p = el;
    for (let i = 0; i < 3 && p; i++) {
      const attrs = [...p.attributes].map(a => a.name + '=' + JSON.stringify(a.value.slice(0, 60))).join(' ');
      chain.push(p.tagName.toLowerCase() + (p.className ? '.' + String(p.className).split(/\\s+/).join('.') : '') + (attrs ? ' [' + attrs + ']' : ''));
      p = p.parentElement;
    }
    out.push({
      text: t,
      html: el.outerHTML.slice(0, 220),
      parent: chain[0] || null,
      grandparent: chain[1] || null,
      great: chain[2] || null,
    });
  }
  return JSON.stringify(out, null, 1);
})()
`;

const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: false });
if (r.exceptionDetails) {
  console.log('eval error:', JSON.stringify(r.exceptionDetails).slice(0, 400));
  process.exit(1);
}
const rows = JSON.parse(r.result.value);
console.log(`\n=== ${rows.length} text node(s) containing "${NEEDLE}" ===`);
for (const [i, row] of rows.entries()) {
  console.log(`\n[${i}] text: ${JSON.stringify(row.text)}`);
  console.log(`    parent      : ${row.parent}`);
  console.log(`    grandparent : ${row.grandparent}`);
  console.log(`    html        : ${row.html}`);
}
ws.close();
