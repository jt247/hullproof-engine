const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const fs = require('node:fs');
const db = require('./db');
const audit = require('./audit');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, ['image/png', 'image/jpeg'].includes(file.mimetype)) });
const loginLimiter = rateLimit({ windowMs: 60000, max: 10 });
const ALLOWED_HOSTS = new Set(['example.com']);
app.use(express.json());

function requireUser(req, res, next) {
  const user = jwt.verify(String(req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET);
  if (!user) return res.status(401).end();
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).end();
  next();
}

const NoteBody = z.object({ title: z.string().min(1).max(200) });

app.post('/api/notes', requireUser, (req, res) => {
  const body = NoteBody.parse(req.body);
  db.run('INSERT INTO notes (title, owner_id) VALUES (?, ?)', [body.title, req.user.id]);
  res.json({ ok: true });
});

app.get('/api/export', requireUser, (req, res) => {
  res.json(db.all('SELECT id, email FROM users WHERE id = ?', [req.user.id]));
});

app.delete('/api/notes/:id', requireUser, (req, res) => {
  db.run('DELETE FROM notes WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

const RoleBody = z.object({ id: z.string(), role: z.enum(['member', 'admin']) });

app.post('/api/admin/users', requireUser, requireAdmin, (req, res) => {
  const body = RoleBody.parse(req.body);
  db.run('UPDATE users SET role = ? WHERE id = ?', [body.role, body.id]);
  audit.record({ actor: req.user.id, action: 'set_role', target: body.id });
  res.json({ ok: true });
});

app.post('/api/login', loginLimiter, (req, res) => {
  const { email, password } = z.object({ email: z.string().email(), password: z.string() }).parse(req.body);
  if (!db.get('SELECT id FROM users WHERE email = ? AND password_hash = ?', [email, password])) return res.status(401).end();
  const next = String(req.query.next || '');
  res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');
});

app.post('/webhooks/pay', (req, res) => {
  const ok = verifySignature(req.rawBody, req.headers['x-pay-signature']);
  if (!ok) return res.status(400).end();
  db.run('UPDATE accounts SET paid = 1 WHERE id = ?', [req.body.account]);
  res.json({ received: true });
});

app.post('/api/import', requireUser, async (req, res) => {
  const { url } = z.object({ url: z.string().url() }).parse(req.body);
  if (!ALLOWED_HOSTS.has(new URL(url).hostname)) return res.status(400).end();
  const page = await fetch(url);
  res.send(await page.text());
});

app.post('/api/upload', requireUser, upload.single('file'), (req, res) => {
  fs.writeFileSync('uploads/' + Date.now(), req.file.buffer);
  res.json({ ok: true });
});

app.get('/api/items', requireUser, (req, res) => {
  const limit = Math.min(Number(req.query.limit || 50), 100);
  res.json(db.all('SELECT * FROM items WHERE owner_id = ? LIMIT ?', [req.user.id, limit]));
});

app.listen(3000);
