// Dirige a página do Chrome da captura (same-origin com o testserver h1) via
// um segundo cliente CDP. Cada caso grava o que a PÁGINA enviou/recebeu
// (sha256) para comparar com cdp-bodies.jsonl e com o servidor.
// uso: node drive.mjs <tmpdir> <base-url> <out.json> <stop-file>
import fs from 'node:fs';
import path from 'node:path';

const [tmpdir, base, outPath, stopFile] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function findPort() {
  for (let i = 0; i < 300; i++) {
    for (const d of fs.existsSync(tmpdir) ? fs.readdirSync(tmpdir) : []) {
      if (!d.startsWith('scrapelens-chrome-')) continue;
      const f = path.join(tmpdir, d, 'DevToolsActivePort');
      if (fs.existsSync(f)) {
        const port = fs.readFileSync(f, 'utf8').split('\n')[0];
        if (port) return port;
      }
    }
    await sleep(200);
  }
  throw new Error('DevToolsActivePort não apareceu');
}

const port = await findPort();
let page;
for (let i = 0; i < 100 && !page; i++) {
  const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  page = list.find((t) => t.type === 'page' && t.url.startsWith(base));
  if (!page) await sleep(200);
}
if (!page) throw new Error('página da captura não encontrada');

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let nextId = 1;
const pending = new Map();
ws.onmessage = (m) => {
  const v = JSON.parse(m.data);
  if (v.id && pending.has(v.id)) pending.get(v.id)(v);
};
const call = (method, params) =>
  new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    ws.send(JSON.stringify({ id, method, params }));
  });

const expression = `(async () => {
  const hex = async (buf) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))].map(b => b.toString(16).padStart(2, '0')).join('');
  const enc = new TextEncoder();
  const binary = new Uint8Array(4099);
  for (let i = 0; i < 4096; i++) binary[i] = (i * 7 + 0xA5) & 0xFF;
  binary.set([0xFF, 0xC0, 0x00], 4096);
  const line = enc.encode('scrapelens-big-body 0123456789abcdef synthetic line\\n');
  const big = new Uint8Array(6 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = line[i % line.length];
  const bigbin = new Uint8Array(6 * 1024 * 1024);
  for (let i = 0; i < bigbin.length; i++) bigbin[i] = (i * 13 + 0x91) & 0xFF;
  const form = 'cmd_consultar_placa=1&placa=TST0T00&obs=a%20b%2Bc&acento=%C3%A9';
  const json = JSON.stringify({cmd: 'cmd_consultar_placa', placa: 'TST0T00', n: [1, 2, 3], u: 'é'});
  const cases = [
    ['form', 'POST', '/sink?case=form', 'application/x-www-form-urlencoded', enc.encode(form)],
    ['json', 'POST', '/sink?case=json', 'application/json', enc.encode(json)],
    ['binary', 'POST', '/sink?case=binary', 'application/octet-stream', binary],
    ['echo_binary', 'POST', '/echo?case=echo_binary', 'application/octet-stream', binary],
    ['big_post', 'POST', '/sink?case=big_post', 'text/plain', big],
    ['big_binary_post', 'POST', '/sink?case=big_binary_post', 'application/octet-stream', bigbin],
    ['r307', 'POST', '/redirect307?case=r307', 'application/x-www-form-urlencoded', enc.encode(form)],
    ['r302', 'GET', '/redirect302?case=r302'],
    ['gzip', 'GET', '/gzip?case=gzip'],
    ['binary_get', 'GET', '/binary?case=binary_get'],
    ['big_get', 'GET', '/big?mib=6&case=big_get'],
    ['json_get', 'GET', '/json?case=json_get'],
    ['latin1', 'GET', 'http://127.0.0.1:' + (Number(location.port) + 1) + '/latin1?case=latin1'],
    ['empty204', 'GET', '/empty?case=empty204'],
    ['zero', 'GET', '/zero?case=zero'],
  ];
  const out = [];
  for (const [name, method, url, ctype, body] of cases) {
    const rec = { case: name, method, url };
    try {
      const init = { method, cache: 'no-store' };
      if (body) { init.body = body; init.headers = { 'content-type': ctype }; rec.sentLen = body.length; rec.sentSha = await hex(body); }
      const r = await fetch(url, init);
      const buf = await r.arrayBuffer();
      rec.status = r.status; rec.finalUrl = r.url; rec.recvLen = buf.byteLength; rec.recvSha = await hex(buf);
      if (url.includes('/sink')) { try { rec.serverReport = JSON.parse(new TextDecoder().decode(buf)); } catch {} }
    } catch (e) { rec.error = String(e); }
    out.push(rec);
  }
  const f = { case: 'refused', method: 'GET', url: 'http://127.0.0.1:59999/refused?case=refused' };
  try { await fetch(f.url, { mode: 'no-cors' }); } catch (e) { f.error = String(e); }
  out.push(f);
  return JSON.stringify(out);
})()`;

const res = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, timeout: 120000 });
if (res.result?.exceptionDetails) throw new Error(JSON.stringify(res.result.exceptionDetails));
fs.writeFileSync(outPath, res.result.result.value);
await sleep(2500);
fs.writeFileSync(stopFile, 'stop\n');
ws.close();
