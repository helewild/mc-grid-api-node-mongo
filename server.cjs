// server.cjs — returns { ok, who, where, rank, at }
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';
const TS_DRIFT_SEC = Number(process.env.TS_DRIFT_SEC || 60);

const app = express();

app.use((req, res, next) => { console.log(`${req.method} ${req.url}`); next(); });

app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

app.use(cors({ origin: true, methods: ['POST','GET','OPTIONS'], allowedHeaders: ['Content-Type','X-Sig'] }));

const sig = (secret, raw) =>
  crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0,8);

// pretend rank DB (swap for real DB later)
function lookupRank(avatarId) {
  // You can customize per avatarId. Default to "Prospect".
  return 'Prospect';
}

app.get('/', (_req,res)=>res.type('text/plain').send('OK'));
app.get('/api/register', (_req,res)=>res.json({ ok:true, info:'POST JSON with ?sig= or X-Sig' }));

app.post('/api/register', (req,res)=>{
  const raw = req.rawBody || '';
  const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
  const want = sig(SHARED_SECRET, raw);

  if(!got) return res.status(400).json({ ok:false, error:'Missing signature (X-Sig or ?sig=)' });
  if(got!==want) return res.status(401).json({ ok:false, error:'Bad sig', recvSig:got, expected:want });

  const d = req.body || {};
  const now = Math.floor(Date.now()/1000);
  const ts  = Number(d.timestamp);
  if(!Number.isFinite(ts) || Math.abs(now - ts) > TS_DRIFT_SEC)
    return res.status(400).json({ ok:false, error:'Stale or invalid timestamp' });

  const rank = lookupRank(d.avatar_id);
  return res.json({
    ok: true,
    who: d.avatar_name,
    where: d.region,
    rank,
    at: new Date().toISOString()
  });
});

app.listen(PORT, ()=>console.log(`HUD API listening on :${PORT}`));
