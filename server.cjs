// server.cjs
// Hardened SL HUD API with:
// - Signature verify (SHA1 first 8 over SECRET + "|" + rawJSON)
// - Replay window (±60s)
// - Tiny IP rate limit
// - Registry persistence (in‑memory) on /api/register
// - New /api/scan to look up MC, Rank, Age(days) for a list of avatar UUIDs

const express = require('express');
const crypto  = require('crypto');
const cors    = require('cors');

const PORT          = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC  = Number(process.env.TS_DRIFT_SEC || 60);
const RATE_PER_MIN  = Number(process.env.RATE_PER_MIN || 120); // a bit higher for scan bursts

const app = express();

// --- tiny per‑IP rate limiter ---
const hits = new Map(); // ip -> {count,last}
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const h = hits.get(ip) || { count: 0, last: now };
  if (now - h.last > 60_000) { h.count = 0; h.last = now; }
  if (++h.count > RATE_PER_MIN) return res.status(429).json({ ok:false, error:'Too many requests' });
  hits.set(ip, h);
  next();
});

// --- raw JSON capture (for exact hashing) ---
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

app.use(cors({
  origin: true,
  methods: ['POST','GET','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Sig']
}));

// --- force plain JSON back (avoid gzip weirdness) ---
app.use((_req, res, next) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.set('Content-Encoding', 'identity');
  res.set('Cache-Control', 'no-store');
  next();
});

// --- helpers ---
const sigSHA1 = (secret, raw) =>
  crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0,8);

const withinWindow = (ts) => {
  const now = Math.floor(Date.now()/1000);
  return Number.isFinite(ts) && Math.abs(now - ts) <= TS_DRIFT_SEC;
};

// --- pretend "DB" (memory) ---
// NOTE: This resets on deploy. Swap to Redis/DB if you need persistence.
const registry = new Map(); // avatar_id -> { name, mc, rank, first_seen, last_seen }
const DEFAULT_MC   = 'MC Grid Wide';
const DEFAULT_RANK = 'Prospect';

function lookupRankFor(id) {
  // TODO: customize per UUID
  return DEFAULT_RANK;
}

// --- simple request log ---
app.use((req,_res,next)=>{ console.log(`${req.method} ${req.url}`); next(); });

// --- health & helpful GET ---
app.get('/', (_req,res)=>res.type('text/plain').send('OK'));
app.get('/api/register', (_req,res)=>res.status(200).send(JSON.stringify({ ok:true, info:'POST JSON with ?sig= or X-Sig' })));

// --- REGISTER: store (or refresh) player in registry ---
app.post('/api/register', (req,res)=>{
  try {
    const raw = req.rawBody || '';
    const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const want = sigSHA1(SHARED_SECRET, raw);
    if (!got) return res.status(400).send(JSON.stringify({ ok:false, error:'Missing signature (X-Sig or ?sig=)' }));
    if (got !== want) return res.status(401).send(JSON.stringify({ ok:false, error:'Bad sig', recvSig:got, expected:want }));

    const d  = req.body || {};
    const ts = Number(d.timestamp);
    if (!withinWindow(ts)) return res.status(400).send(JSON.stringify({ ok:false, error:'Stale or invalid timestamp' }));

    const id   = String(d.avatar_id || '');
    const name = String(d.avatar_name || '');
    const nowS = Math.floor(Date.now()/1000);

    const existing = registry.get(id);
    if (existing) {
      existing.name = name || existing.name;
      existing.last_seen = nowS;
      registry.set(id, existing);
    } else {
      registry.set(id, {
        name: name || '(unknown)',
        mc: DEFAULT_MC,
        rank: lookupRankFor(id),
        first_seen: nowS,
        last_seen:  nowS
      });
    }

    const r = registry.get(id);
    const out = { ok:true, who:r.name, where:String(d.region||''), rank:r.rank, at:new Date().toISOString() };
    return res.status(200).send(JSON.stringify(out));
  } catch (e) {
    console.error(e); return res.status(500).send(JSON.stringify({ ok:false, error:'Server error' }));
  }
});

// --- SCAN: look up a list of avatar UUIDs, return MC/Rank/Age(days) ---
app.post('/api/scan', (req,res)=>{
  try {
    const raw = req.rawBody || '';
    const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const want = sigSHA1(SHARED_SECRET, raw);
    if (!got) return res.status(400).send(JSON.stringify({ ok:false, error:'Missing signature (X-Sig or ?sig=)' }));
    if (got !== want) return res.status(401).send(JSON.stringify({ ok:false, error:'Bad sig' }));

    const d  = req.body || {};
    const ts = Number(d.timestamp);
    if (!withinWindow(ts)) return res.status(400).send(JSON.stringify({ ok:false, error:'Stale or invalid timestamp' }));

    const ids = Array.isArray(d.targets) ? d.targets : [];
    const nowS = Math.floor(Date.now()/1000);

    const results = ids.slice(0, 20).map((id) => {
      const rec = registry.get(String(id));
      if (!rec) {
        return { id, who: '(unknown)', mc: '(unknown)', rank: '(unknown)', age_days: 0 };
      }
      const ageDays = Math.max(0, Math.floor((nowS - (rec.first_seen || nowS))/86400));
      return { id, who: rec.name, mc: rec.mc, rank: rec.rank, age_days: ageDays };
    });

    return res.status(200).send(JSON.stringify({ ok:true, results }));
  } catch (e) {
    console.error(e); return res.status(500).send(JSON.stringify({ ok:false, error:'Server error' }));
  }
});

app.listen(PORT, () => {
  console.log(`HUD API listening on http://0.0.0.0:${PORT}`);
  console.log(`Secret set? ${SHARED_SECRET !== 'CHANGEME_SECRET' ? 'yes' : 'USING DEFAULT (change in prod!)'}`);
});
