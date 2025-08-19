// server.cjs
// Hardened SL HUD API: signature verify, replay protection, rate limit, friendly response.

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC = Number(process.env.TS_DRIFT_SEC || 60); // replay window
const RATE_PER_MIN = Number(process.env.RATE_PER_MIN || 60); // ip limit per minute

const app = express();

// ----- simple IP rate limiter -----
const hits = new Map(); // ip -> {count,last}
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const stat = hits.get(ip) || { count: 0, last: now };
  if (now - stat.last > 60_000) { stat.count = 0; stat.last = now; }
  if (++stat.count > RATE_PER_MIN) {
    return res.status(429).json({ ok: false, error: 'Too many requests' });
  }
  hits.set(ip, stat);
  next();
});

// capture raw JSON exactly as sent by HUD
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

app.use(cors({
  origin: true,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Sig']
}));

// --- signature helpers ---
// SHA-1 (LSL-standard)
function sig_sha1(secret, raw) {
  return crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0, 8);
}

// If you later add SHA-256 in LSL, swap to this and update the HUD:
// function sig_sha256(secret, raw) {
//   return crypto.createHash('sha256').update(secret + '|' + raw, 'utf8').digest('hex').slice(0, 8);
// }

app.get('/', (_req, res) => res.type('text/plain').send('OK'));

app.post('/api/register', (req, res) => {
  try {
    const raw = req.rawBody || '';
    // accept either header or query (?sig=...)
    const gotSig = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const wantSig = sig_sha1(SHARED_SECRET, raw);

    // debug line (safe): comment out if you prefer silence
    console.log('POST /api/register gotSig=%s wantSig=%s rawLen=%d', gotSig, wantSig, raw.length);

    if (!gotSig) {
      return res.status(400).json({ ok: false, error: 'Missing signature (X-Sig or ?sig=)' });
    }
    if (gotSig !== wantSig) {
      return res.status(401).json({ ok: false, error: 'Bad sig', recvSig: gotSig, expected: wantSig });
    }

    const data = req.body || {};

    // --- replay protection (±60s by default) ---
    const now = Math.floor(Date.now() / 1000);
    const ts = Number(data.timestamp);
    if (!Number.isFinite(ts) || Math.abs(now - ts) > TS_DRIFT_SEC) {
      return res.status(400).json({ ok: false, error: 'Stale or invalid timestamp' });
    }

    // friendly, compact response
    return res.json({
      ok: true,
      who: data.avatar_name,
      where: data.region,
      at: new Date().toISOString()
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`HUD API listening on http://0.0.0.0:${PORT}`);
  console.log(`Secret set? ${SHARED_SECRET !== 'CHANGEME_SECRET' ? 'yes' : 'USING DEFAULT (change in prod!)'}`);
});
