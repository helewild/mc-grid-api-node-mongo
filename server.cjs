// server.cjs (identity responses, same hardened behavior)
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC = Number(process.env.TS_DRIFT_SEC || 60);
const RATE_PER_MIN = Number(process.env.RATE_PER_MIN || 60);

const app = express();

// tiny IP rate limit
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const h = hits.get(ip) || { count: 0, last: now };
  if (now - h.last > 60_000) { h.count = 0; h.last = now; }
  if (++h.count > RATE_PER_MIN) return res.status(429).json({ ok: false, error: 'Too many requests' });
  hits.set(ip, h);
  next();
});

// capture raw body exactly
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

app.use(cors({ origin: true, methods: ['POST','GET','OPTIONS'], allowedHeaders: ['Content-Type','X-Sig'] }));

// force identity (no gzip) so SL gets a plain body
app.use((req, res, next) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.set('Content-Encoding', 'identity');
  res.set('Cache-Control', 'no-store');
  next();
});

// signature helper
const sigSHA1 = (secret, raw) =>
  crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0,8);

// logs
app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next(); });

// health + GET helper
app.get('/', (_req, res) => res.type('text/plain').send('OK'));
app.get('/api/register', (_req, res) =>
  res.status(200).send(JSON.stringify({ ok:true, info:'POST JSON with ?sig= or X-Sig' }))
);

// toy rank lookup
const lookupRank = (avatarId) => 'Prospect';

app.post('/api/register', (req, res) => {
  try {
    const raw = req.rawBody || '';
    const gotSig = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const wantSig = sigSHA1(SHARED_SECRET, raw);

    if (!gotSig) return res.status(400).send(JSON.stringify({ ok:false, error:'Missing signature (X-Sig or ?sig=)' }));
    if (gotSig !== wantSig) return res.status(401).send(JSON.stringify({ ok:false, error:'Bad sig', recvSig:gotSig, expected:wantSig }));

    const d = req.body || {};
    const now = Math.floor(Date.now()/1000);
    const ts  = Number(d.timestamp);
    if (!Number.isFinite(ts) || Math.abs(now - ts) > TS_DRIFT_SEC)
      return res.status(400).send(JSON.stringify({ ok:false, error:'Stale or invalid timestamp' }));

    const rank = lookupRank(d.avatar_id);
    const out  = { ok:true, who:d.avatar_name, where:d.region, rank, at:new Date().toISOString() };

    // send as a pre-serialized string to avoid any proxy encoding tricks
    res.status(200).send(JSON.stringify(out));
  } catch (e) {
    console.error(e);
    res.status(500).send(JSON.stringify({ ok:false, error:'Server error' }));
  }
});

app.listen(PORT, () => {
  console.log(`HUD API listening on http://0.0.0.0:${PORT}`);
  console.log(`Secret set? ${SHARED_SECRET !== 'CHANGEME_SECRET' ? 'yes' : 'USING DEFAULT (change in prod!)'}`);
});
