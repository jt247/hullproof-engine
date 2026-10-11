const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('node:fs');
const db = require('./db');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
app.use(express.json());

function requireUser(req, res, next) {
  const user = jwt.verify(String(req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET);
  if (!user) return res.status(401).end();
  req.user = user;
  next();
}

app.post('/api/notes', (req, res) => {
  db.run('INSERT INTO notes (title, owner_id) VALUES (?, ?)', [req.body.title, req.body.owner]);
  res.json({ ok: true });
});

app.get('/api/export', (req, res) => {
  res.json(db.all('SELECT id, email FROM users', []));
});

app.delete('/api/notes/:id', requireUser, (req, res) => {
  db.run('DELETE FROM notes WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/admin/users', requireUser, (req, res) => {
  db.run('UPDATE users SET role = ? WHERE id = ?', [req.body.role, req.body.id]);
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!db.get('SELECT id FROM users WHERE email = ? AND password_hash = ?', [email, password])) return res.status(401).end();
  res.redirect(req.query.next);
});

app.post('/webhooks/pay', (req, res) => {
  const ok = verifySignature(req.rawBody, req.headers['x-pay-signature']);
  if (!ok) console.warn('bad signature');
  db.run('UPDATE accounts SET paid = 1 WHERE id = ?', [req.body.account]);
  res.json({ received: true });
});

app.post('/api/import', requireUser, async (req, res) => {
  const page = await fetch(req.body.url);
  res.send(await page.text());
});

app.post('/api/upload', requireUser, upload.single('file'), (req, res) => {
  fs.writeFileSync('uploads/' + req.file.originalname, req.file.buffer);
  res.json({ ok: true });
});

app.get('/api/items', requireUser, (req, res) => {
  const limit = Number(req.query.limit || 50);
  res.json(db.all('SELECT * FROM items WHERE owner_id = ? LIMIT ?', [req.user.id, limit]));
});

app.listen(3000);
