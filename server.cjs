// server.cjs — Register + Scan API for SL HUD (hardened + identity responses)
const express = require('express');
const crypto  = require('crypto');
const cors    = require('cors');

const PORT          = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC  = Number(process.env.TS_DRIFT_SEC || 60);
const RATE_PER_MIN  = Number(process.env.RATE_PER_MIN || 120);

const app = express();

// tiny per‑IP rate limiter
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const h = hits.get(ip) || { count: 0, last: now };
  if (now - h.last > 60_000) { h.count = 0; h.last = now; }
  if (++h.count > RATE_PER_MIN) return res.status(429).json({ ok:false, error:'Too many requests' });
  hits.set(ip, h);
  next();
});

// capture exact raw JSON for signature
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }}));
app.use(cors({ origin:true, methods:['POST','GET','OPTIONS'], allowedHeaders:['Content-Type','X-Sig'] }));

// force identity (some SL viewers choke on gzip)
app.use((_req, res, next) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.set('Content-Encoding', 'identity');
  res.set('Cache-Control', 'no-store');
  next();
});

const sig = (secret, raw) =>
  crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0,8);

const fresh = (ts) => {
  const now = Math.floor(Date.now()/1000);
  return Number.isFinite(ts) && Math.abs(now - ts) <= TS_DRIFT_SEC;
};

// in‑memory registry
const registry = new Map(); // id -> { name, mc, rank, first_seen, last_seen }
const DEFAULT_MC   = 'MC Grid Wide';
const DEFAULT_RANK = 'Prospect';
const lookupRank = (_id) => DEFAULT_RANK;

// logs + helpers
app.use((req,_res,next)=>{ console.log(`${req.method} ${req.url}`); next(); });
app.get('/', (_req,res)=>res.type('text/plain').send('OK'));
app.get('/api/register', (_req,res)=>res.status(200).send(JSON.stringify({ ok:true, info:'POST JSON with ?sig= or X-Sig' })));

// REGISTER
app.post('/api/register', (req,res)=>{
  try {
    const raw = req.rawBody || '';
    const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const want = sig(SHARED_SECRET, raw);
    if (!got) return res.status(400).send(JSON.stringify({ ok:false, error:'Missing signature (X-Sig or ?sig=)' }));
    if (got !== want) return res.status(401).send(JSON.stringify({ ok:false, error:'Bad sig' }));

    const d  = req.body || {};
    if (!fresh(Number(d.timestamp))) return res.status(400).send(JSON.stringify({ ok:false, error:'Stale or invalid timestamp' }));

    const id   = String(d.avatar_id || '');
    const name = String(d.avatar_name || '');
    const nowS = Math.floor(Date.now()/1000);

    const rec = registry.get(id);
    if (rec) {
      rec.name = name || rec.name;
      rec.last_seen = nowS;
    } else {
      registry.set(id, { name: name || '(unknown)', mc: DEFAULT_MC, rank: lookupRank(id), first_seen: nowS, last_seen: nowS });
    }
    const r = registry.get(id);
    res.status(200).send(JSON.stringify({ ok:true, who:r.name, where:String(d.region||''), rank:r.rank, at:new Date().toISOString() }));
  } catch (e) {
    console.error(e); res.status(500).send(JSON.stringify({ ok:false, error:'Server error' }));
  }
});

// SCAN
app.post('/api/scan', (req,res)=>{
  try {
    const raw = req.rawBody || '';
    const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
    const want = sig(SHARED_SECRET, raw);
    if (!got) return res.status(400).send(JSON.stringify({ ok:false, error:'Missing signature (X-Sig or ?sig=)' }));
    if (got !== want) return res.status(401).send(JSON.stringify({ ok:false, error:'Bad sig' }));

    const d  = req.body || {};
    if (!fresh(Number(d.timestamp))) return res.status(400).send(JSON.stringify({ ok:false, error:'Stale or invalid timestamp' }));

    const ids = Array.isArray(d.targets) ? d.targets : [];
    const nowS = Math.floor(Date.now()/1000);

    const results = ids.slice(0, 50).map((id) => {
      const rec = registry.get(String(id));
      if (!rec) return { id, who:'(unknown)', mc:'(unknown)', rank:'(unknown)', age_days:0 };
      const ageDays = Math.max(0, Math.floor((nowS - (rec.first_seen || nowS))/86400));
      return { id, who:rec.name, mc:rec.mc, rank:rec.rank, age_days:ageDays };
    });

    res.status(200).send(JSON.stringify({ ok:true, results }));
  } catch (e) {
    console.error(e); res.status(500).send(JSON.stringify({ ok:false, error:'Server error' }));
  }
});

app.listen(PORT, () => {
  console.log(`HUD API listening on http://0.0.0.0:${PORT}`);
  console.log(`Secret set? ${SHARED_SECRET !== 'CHANGEME_SECRET' ? 'yes' : 'USING DEFAULT (change in prod!)'}`);
});
