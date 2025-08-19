// server.cjs
// Minimal Express API that verifies a short SHA1-based signature from your SL HUD.
// sig = first 8 hex chars of SHA1( SECRET + "|" + rawJsonBody )

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';

const app = express();

// Capture raw request body exactly as sent by the HUD.
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

app.use(cors({
  origin: true,
  methods: ['POST', 'OPTIONS', 'GET'],
  allowedHeaders: ['Content-Type', 'X-Sig'],
}));

function computeSig(secret, raw) {
  const h = crypto.createHash('sha1');
  h.update(secret + '|' + raw, 'utf8');
  return h.digest('hex').slice(0, 8);
}

app.get('/', (_req, res) => res.type('text/plain').send('OK'));

app.post('/api/register', (req, res) => {
  try {
    const raw = req.rawBody || '';
    const gotSig = (req.get('X-Sig') || '').trim().toLowerCase();
    const wantSig = computeSig(SHARED_SECRET, raw);

    console.log('POST /api/register gotSig=%s wantSig=%s rawLen=%d', gotSig, wantSig, raw.length);

    if (!gotSig) {
      return res.status(400).json({ ok: false, error: 'Missing X-Sig header' });
    }
    if (gotSig !== wantSig) {
      return res.status(401).json({ ok: false, error: 'Bad sig', recvSig: gotSig, expected: wantSig });
    }

    const data = req.body || {};
    return res.json({
      ok: true,
      message: 'Registered',
      echo: {
        avatar_id: data.avatar_id,
        avatar_name: data.avatar_name,
        h
