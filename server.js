// server.js
import express from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import { customAlphabet } from 'nanoid';

dotenv.config();

const SECRET    = process.env.SECRET || 'CHANGEME_SECRET';
const PORT      = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;                 // e.g. mongodb+srv://USER:PASS@cluster.mongodb.net/mcgrid
const MONGO_DB  = process.env.MONGO_DB || 'mcgrid';

const app = express();
app.use(express.json({ limit: '256kb' }));

// Simple health check
app.get('/health', (req, res) => res.type('text/plain').send('OK'));

// Helpers
const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex');

// Tolerant signature verification:
// - trims payload/sig
// - lowercases hex
// - accepts RAW string OR canonicalized JSON (JSON.stringify(obj))
function verifySig(req, res, next) {
  let { payload, sig } = req.body || {};
  if (typeof payload !== 'string' || typeof sig !== 'string') {
    return res.status(400).send('Bad payload');
  }
  payload = payload.trim();
  sig = sig.trim().toLowerCase();

  // 1) Raw string match
  const expectRaw = sha1(SECRET + '|' + payload).toLowerCase();
  if (expectRaw === sig) {
    try { req.data = JSON.parse(payload); } catch { return res.status(400).send('Bad JSON'); }
    return next();
  }

  // 2) Canonical JSON match
  try {
    const obj = JSON.parse(payload);
    const stable = JSON.stringify(obj); // minified, stable order
    const expectStable = sha1(SECRET + '|' + stable).toLowerCase();
    if (expectStable === sig) {
      req.data = obj;
      return next();
    }
  } catch { /* ignore; we'll 401 */ }

  console.warn('[sig-mismatch]', { recvSig: sig.slice(0,8), rawSig: expectRaw.slice(0,8), payloadLen: payload.length });
  return res.status(401).type('text/plain').send('Bad sig');
}

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

async function main() {
  if (!MONGO_URI) {
    console.error('❌ Missing MONGO_URI env var');
    process.exit(1);
  }

  // Connect to Mongo
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db(MONGO_DB);

  // Helpful indexes
  await db.collection('huds').createIndex({ avatar_id: 1 }, { unique: true });
  await db.collection('members').createIndex({ avatar_id: 1 }, { unique: true });
  await db.collection('turf').createIndex({ beacon_id: 1 }, { unique: true });

  // ---------- Routes ----------

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
    const key = req.get('x-auth') || req.get('X-Auth') || req.query.key;
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
      club_id, name: name || 'Club', tag: tag || 'MC', founder_id: founder_id || '', created_at: Date.now()
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
      { $set: { parcel: parcel || '', club_id: club_id || '', score: parseInt(score || 0, 10), updated_at: Date.now() } },
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
}

main().catch(err => {
  console.error('❌ Startup error:', err);
  process.exit(1);
});
