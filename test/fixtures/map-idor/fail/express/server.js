const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();

function requireUser(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch (e) { res.status(401).json({ error: 'sign in' }); }
}

app.get('/api/notes/:id', requireUser, async (req, res) => {
  const note = await db.query('SELECT * FROM notes WHERE id = $1', [req.params.id]);
  res.json(note.rows[0]);
});

app.listen(3000);
