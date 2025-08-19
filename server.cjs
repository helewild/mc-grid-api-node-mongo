// server.cjs
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'CHANGEME_SECRET';

const app = express();
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(cors({ origin: true, methods: ['POST','GET','OPTIONS'], allowedHeaders: ['Content-Type','X-Sig'] }));

function sig(secret, raw){
  return crypto.createHash('sha1').update(secret + '|' + raw, 'utf8').digest('hex').slice(0,8);
}

app.get('/', (_req,res)=>res.type('text/plain').send('OK'));

app.post('/api/register', (req,res)=>{
  const raw = req.rawBody || '';
  const got = ((req.get('X-Sig') || req.query.sig || '') + '').trim().toLowerCase();
  const want = sig(SHARED_SECRET, raw);

  if(!got) return res.status(400).json({ok:false,error:'Missing signature (X-Sig header or ?sig=)'});
  if(got!==want) return res.status(401).json({ok:false,error:'Bad sig',recvSig:got,expected:want});

  const d = req.body || {};
  res.json({ ok:true, message:'Registered', echo:{
    avatar_id:d.avatar_id, avatar_name:d.avatar_name, hud_version:d.hud_version, region:d.region, timestamp:d.timestamp
  }});
});

app.listen(PORT, ()=>console.log(`HUD API listening on :${PORT}`));
