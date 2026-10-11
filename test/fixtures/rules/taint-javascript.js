// Fixture for rules/semgrep/taint-javascript.yaml (Express, Koa and plain Node). Written for the Hullproof Engine.
// Each "ruleid" line must match and each "ok" line must not, checked by semgrep --test in test/rules.test.ts.
const express = require('express');
const child_process = require('child_process');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const mysql = require('mysql2');

const app = express();
const db = mysql.createConnection({});

// ---- SQL injection, CWE-89 ----

app.get('/user', (req, res) => {
  const name = req.query.name;
  // ruleid: hullproof-taint-js-sql-injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'", (e, rows) => res.json(rows));
  // ruleid: hullproof-taint-js-sql-injection
  db.execute(`SELECT * FROM users WHERE id = ${req.params.id}`);
  // ok: hullproof-taint-js-sql-injection
  db.query('SELECT * FROM users WHERE name = ?', [name], (e, rows) => res.json(rows));
  // ok: hullproof-taint-js-sql-injection
  db.query(`SELECT * FROM users WHERE id = ${parseInt(req.params.id, 10)}`);
  // ok: hullproof-taint-js-sql-injection
  db.query('SELECT * FROM users WHERE name = ' + db.escape(name));
});

function report(knex, filter) {
  // ok: hullproof-taint-js-sql-injection
  return knex.raw('SELECT * FROM t WHERE x = ' + filter);
}

// ---- XSS, CWE-79 ----

app.get('/hello', (req, res) => {
  // ruleid: hullproof-taint-js-xss
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

app.get('/hello2', (req, res) => {
  // ok: hullproof-taint-js-xss
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});

app.get('/hello3', (req, res) => {
  // ok: hullproof-taint-js-xss
  res.json({ name: req.query.name });
  // ok: hullproof-taint-js-xss
  res.send({ name: req.query.name });
});

app.post('/echo', (req, res) => {
  // ruleid: hullproof-taint-js-xss
  res.write(`<p>${req.body.comment}</p>`);
  res.end();
});

function showSearch() {
  const q = new URLSearchParams(location.search).get('q');
  // ruleid: hullproof-taint-js-xss
  document.getElementById('out').innerHTML = 'Results for ' + q;
  // ok: hullproof-taint-js-xss
  document.getElementById('out').textContent = 'Results for ' + q;
  // ok: hullproof-taint-js-xss
  document.getElementById('out').innerHTML = DOMPurify.sanitize(q);
}

function koaHandler(ctx) {
  // ruleid: hullproof-taint-js-xss
  ctx.body = '<div>' + ctx.query.msg + '</div>';
}

// ---- Command injection, CWE-78 ----

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // ruleid: hullproof-taint-js-command-injection
  child_process.exec('ping -c 1 ' + host, (e, out) => res.send('done'));
  // ruleid: hullproof-taint-js-command-injection
  child_process.spawn('sh', ['-c', 'ping ' + host]);
  // ruleid: hullproof-taint-js-command-injection
  child_process.execSync(`nslookup ${req.body.domain}`);
  // ok: hullproof-taint-js-command-injection
  execFile('ping', ['-c', '1', host], () => res.send('done'));
  // ok: hullproof-taint-js-command-injection
  child_process.exec('uptime');
});

app.post('/run', (req, res) => {
  // ruleid: hullproof-taint-js-command-injection
  execFile(req.body.tool, ['--version'], () => res.send('done'));
});

// ---- Path traversal, CWE-22 ----

app.get('/file', (req, res) => {
  // ruleid: hullproof-taint-js-path-traversal
  const data = fs.readFileSync(path.join(__dirname, 'files', req.query.name));
  // ok: hullproof-taint-js-path-traversal
  const safe = fs.readFileSync(path.join(__dirname, 'files', path.basename(req.query.name)));
  res.json({ size: data.length + safe.length });
});

app.get('/download', (req, res) => {
  // ruleid: hullproof-taint-js-path-traversal
  res.sendFile('/srv/files/' + req.params.file);
});

app.get('/download2', (req, res) => {
  // ok: hullproof-taint-js-path-traversal
  res.sendFile(req.params.file, { root: '/srv/files' });
});

app.delete('/upload/:name', (req, res) => {
  const target = path.join('/srv/uploads', req.params.name);
  assertInsideRoot(target);
  // ok: hullproof-taint-js-path-traversal
  fs.unlinkSync(target);
  res.sendStatus(204);
});

// ---- SSRF, CWE-918 ----

app.get('/fetch', async (req, res) => {
  // ruleid: hullproof-taint-js-ssrf
  const r = await axios.get(req.query.url);
  // ok: hullproof-taint-js-ssrf
  const s = await axios.get('https://api.example.com/search?q=' + req.query.url);
  // ok: hullproof-taint-js-ssrf
  const t = await axios.get(`https://api.example.com/items/${req.query.id}`);
  res.json({ a: r.status, b: s.status, c: t.status });
});

app.post('/hook-test', async (req, res) => {
  const target = req.body.callbackUrl;
  // ruleid: hullproof-taint-js-ssrf
  await fetch(target, { method: 'POST' });
  res.sendStatus(204);
});

app.post('/hook-test2', async (req, res) => {
  const target = req.body.callbackUrl;
  await validateOutboundUrl(target);
  // ok: hullproof-taint-js-ssrf
  await fetch(target, { method: 'POST' });
  res.sendStatus(204);
});

async function health() {
  // ok: hullproof-taint-js-ssrf
  return fetch('https://status.example.com/health');
}
