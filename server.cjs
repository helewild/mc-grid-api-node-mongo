// server.cjs
// A tiny Express API that verifies a short HMAC-style signature from your SL HUD.
// Signature rule (to keep LSL-friendly):
//   sig = first 8 hex chars of SHA1( SECRET + "|" + rawJsonBody )
// Both sides must use *identical* raw JSON (no extra spaces) to match the hash.

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

// ---- Config ----
const PORT = process.env.PORT || 3000;
// MUST match the HUD's CHANGEME_SECRET in LSL:
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';

// ---- App ----
const app = express();

// We need the raw body string (not parsed/pretty-printed) to hash exactly.
// So, capture raw buffers and also parse JSON afterwards.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);

app.use(
  cors({
    origin: true,
    methods: ['POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Sig'],
  })
);

// util: compute first 8 of sha1(secret + "|" + rawJson)
function computeSig(secret, raw) {
  const h = crypto.createHash('sha1');
  h.update(secret + '|' + raw, 'utf8');
  return h.digest('hex').slice(0, 8);
}

// Simple health
app.get('/', (_req, res) => {
  res.type('text/plain').send('OK');
});

// Registration endpoint the HUD will call
app.post('/api/register', (req, res) => {
  try {
    const raw = req.rawBody || '';
    const gotSig = (req.get('X-Sig') || '').trim().toLowerCase();
    const wantSig = computeSig(SHARED_SECRET, raw);

    if (!gotSig) {
      return res.status(400).json({ ok: false, error: 'Missing X-Sig header' });
    }
    if (gotSig !== wantSig) {
      return res.status(401).json({
        ok: false,
        error: 'Bad sig',
        recvSig: gotSig,
        expected: wantSig,
      });
    }

    // At this point, the signature matched — trust the body.
    const data = req.body || {};
    // You can store/lookup avatars, issue tokens, etc. Here we just echo back.
    return res.json({
      ok: true,
      message: 'Registered',
      echo: {
        avatar_id: data.avatar_id,
        avatar_name: data.avatar_name,
        hud_version: data.hud_version,
        region: data.region,
        timestamp: data.timestamp,
      },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`HUD API listening on http://0.0.0.0:${PORT}`);
  console.log(`Secret: ${SHARED_SECRET}`);
});
