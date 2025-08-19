// server.cjs
// Hardened SL HUD API: signature verify (SHA1 first 8), replay protection,
// small rate limiter, and compact JSON responses.

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC = Number(process.env.TS_DRIFT_SEC || 60);  // ±60s replay window
const RATE_PER_MIN = Number(process.env.RATE_PER_MIN || 60);  // per-IP requests/min

const app = express();

// --- tiny per‑IP rate limiter ---
const hits = new Map(); // ip -> {count,last}
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const h = hits.get(ip) || { count: 0, last: now };
  if (now - h.last > 60_000) { h.count = 0; h.last = now; }
  if (++h.count > RATE_PER_MIN) return res.status(429).json({ ok: false, error: 'Too many requests' });
  hits.set(ip, h);
  next();
});

// --- raw JSON capture (for exact hashing) ---
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

app.use(cors({
  origin: true,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Sig']
}));

// --- signature helper (SHA‑1, first 8 hex chars) ---
function sigSHA1(secret, raw) {
  return crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0, 8);
}

// Log incoming routes to help debug
app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next(); });

// Health
app.get('/', (_req, res) => res.type('text/plain').send('OK'));

// Helpful GET so visiting /api/register in browser doesn’t 404
app.get('/api/register', (_req, res) => {
  res.json({ ok: true, info: 'POST JSON with ?sig= or X-Sig header' });
});

// Pretend “rank DB” — customize per avatar_id as you like
function lookupRank(avatarId) {
  // e.g., return avatarId === 'some-uuid' ? 'Sergeant-at-Arms' : 'Prospect';
  return 'Prospect';
}

app.post('/api/register', (req, res) => {
  try {
    const raw = req.rawBody || '';
    // Accept either header or query param
    const gotSig = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const wantSig = sigSHA1(SHARED_SECRET, raw);

    if (!gotSig) return res.status(400).json({ ok: false, error: 'Missing signature (X-Sig or ?sig=)' });
    if (gotSig !== wantSig) return res.status(401).json({ ok: false, error: 'Bad sig', recvSig: gotSig, expected: wantSig });

    const d = req.body || {};

    // Replay protection using client timestamp
    const now = Math.floor(Date.now() / 1000);
    const ts = Number(d.timestamp);
    if (!Number.isFinite(ts) || Math.abs(now - ts) > TS_DRIFT_SEC) {
      return res.status(400).json({ ok: false, error: 'Stale or invalid timestamp' });
    }

    const rank = lookupRank(d.avatar_id);

    // Friendly compact response (HUD reads rank + who)
    return res.json({
      ok: true,
      who: d.avatar_name,
      where: d.region,
      rank,
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
