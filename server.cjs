// server.cjs (CommonJS, robust signature handling + compat variants)
const express = require('express');
const dotenv = require('dotenv');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const { customAlphabet } = require('nanoid');

dotenv.config();

const SECRET    = process.env.SECRET || 'CHANGEME_SECRET';
const PORT      = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const MONGO_DB  = process.env.MONGO_DB || 'mcgrid';

const app = express();
app.use(express.json({ limit: '256kb' }));

// Health check
app.get('/health', (req, res) => res.type('text/plain').send('OK'));

// Helpers
const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex');

// Ultra-tolerant signature verifier with compat variants + diagnostics
function verifySig(req, res, next) {
  // If the whole body arrived as a string, try to parse it
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch { /* keep as string */ }
  }

  let payload = req.body && req.body.payload;
  let sig     = req.body && req.body.sig;

  // If payload is an object, canonicalize it to a string
  if (payload && typeof payload === 'object') {
    try { payload = JSON.stringify(payload); } catch {}
  }

  if (typeof payload !== 'string' || typeof sig !== 'string') {
    return res.status(400).type('text/plain').send('Bad payload');
  }

  const sigLower = sig.trim().toLowerCase();

  // Build candidate payload variants to hash
  const candidates = [];
  // 1) RAW (exact) — do NOT trim/modify
  candidates.push(payload);
  // 2) Canonical JSON (parse + stringify)
  try { candidates.push(JSON.stringify(JSON.parse(payload))); } catch {}

  // 3) Common wire-format quirks (harmless to try)
  // a) \/ vs /
  candidates.push(payload.replace(/\\\//g, '/'));
  // b) line-ending normalization
  candidates.push(payload.replace(/\r\n/g, '\n'));
  candidates.push(payload.replace(/\n/g, '\r\n'));
  // c) trailing newline variants
  candidates.push(payload + '\n');
  candidates.push(payload + '\r\n');

  // Try each candidate
  for (const cand of candidates) {
    if (typeof cand !== 'string') continue;
    const h = sha1(SECRET + '|' + cand).toLowerCase();
    if (h === sigLower) {
      // Success: parse data from the matching candidate
      try { req.data = JSON.parse(cand); }
      catch { return res.status(400).type('text/plain').send('Bad JSON'); }
      return next();
    }
  }

  // If none matched, log short diagnostics (safe—does not expose secret)
  const rawSig = sha1(SECRET + '|' + payload).toLowerCase();
  let stableSig = '';
  try { stableSig = sha1(SECRET + '|' + JSON.stringify(JSON.parse(payload))).toLowerCase(); } catch {}
  console.warn('[sig-mismatch]', {
    recvSig: sigLower.slice(0,8),
    rawSig: rawSig.slice(0,8),
    stableSig: stableSig.slice(0,8),
    payloadLen: payload.length,
    payloadFirst80: payload.slice(0,80)
  });

  return res.status(401).type('text/plain').send('Bad sig');
}

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

// Async startup wrapper (no top-level await)
(async () => {
  try {
    if (!MONGO_URI) {
      console.error('❌ Missing MONGO_URI env var');
      process.exit(1);
    }

    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(MONGO_DB);

    // Helpful indexes
    await db.collection('huds').createIndex({ avatar_id: 1 }, { unique: true });
    await db.collection('members').createIndex({ avatar_id: 1 }, { unique: true });
    await db.collection('turf').createIndex({ beacon_id: 1 }, { unique: true });

    // ------------------ Routes ------------------

    // Register HUD (signed)
    app.post('/v1/hud/register', verifySig, async (req, res) => {
      const { avatar_id, avatar_name, url } = req.data;
      await db.collection('huds').updateOne(
        { avatar_id },
        { $set: { avatar_name: avatar_name || '', url: url || '', updated_at: Date.now() } },
        { upsert: true }
      );
      res.type('text/plain').send('OK');
    });

    // HUD heartbeat (signed)
    app.post('/v1/hud/heartbeat', verifySig, async (req, res) => {
      const { avatar_id } = req.data;
      await db.collection('huds').updateOne(
        { avatar_id },
        { $set: { updated_at: Date.now() } }
      );
      res.type('text/plain').send('OK');
    });

    // List HUD endpoints (auth via header or ?key=)
    app.get('/v1/hud/endpoints', async (req, res) => {
      const key = req.get('x-auth') || req.get('X-Auth') || (req.query && req.query.key);
      if (key !== SECRET) return res.status(401).type('text/plain').send('No');

      const huds = await db.collection('huds')
        .find({ url: { $exists: true, $ne: '' } })
        .project({ _id: 0, avatar_id: 1, url: 1 })
        .toArray();

      res.type('text/plain').send(huds.map(h => `${h.avatar_id},${h.url}`).join('\n'));
    });

    // Create club (signed)
    app.post('/v1/club/create', verifySig, async (req, res) => {
      const { name, tag, founder_id } = req.data;
      const club_id = nanoid();
      await db.collection('clubs').insertOne({
        club_id,
        name: name || 'Club',
        tag: tag || 'MC',
        founder_id: founder_id || '',
        created_at: Date.now()
      });
      await db.collection('members').updateOne(
        { avatar_id: founder_id },
        { $set: { club_id, rank: 'Prez' } },
        { upsert: true }
      );
      res.json({ club_id });
    });

    // Set member (signed)
    app.post('/v1/member/set', verifySig, async (req, res) => {
      const { avatar_id, club_id, rank } = req.data;
      await db.collection('members').updateOne(
        { avatar_id },
        { $set: { club_id, rank: rank || 'Member' } },
        { upsert: true }
      );
      res.type('text/plain').send('OK');
    });

    // Update turf (signed)
    app.post('/v1/turf/update', verifySig, async (req, res) => {
      const { beacon_id, parcel, club_id, score } = req.data;
      await db.collection('turf').updateOne(
        { beacon_id },
        { $set: {
            parcel: parcel || '',
            club_id: club_id || '',
            score: parseInt(score || 0, 10),
            updated_at: Date.now()
          } },
        { upsert: true }
      );
      res.type('text/plain').send('OK');
    });

    // Turf summary (public)
    app.get('/v1/turf/summary', async (req, res) => {
      const rows = await db.collection('turf')
        .find({}, { projection: { _id: 0 } })
        .sort({ updated_at: -1 })
        .toArray();
      res.json(rows);
    });

    // Start server
    app.listen(PORT, () => console.log('✅ API (Node + Mongo) running on :' + PORT));
  } catch (err) {
    console.error('❌ Startup error:', err);
    process.exit(1);
  }
})();
