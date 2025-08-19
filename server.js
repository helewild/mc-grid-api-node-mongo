import express from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import { customAlphabet } from 'nanoid';

dotenv.config();
const app = express();
app.use(express.json({ limit: '256kb' }));

const SECRET = process.env.SECRET || 'CHANGEME_SECRET';
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;
const MONGO_DB = process.env.MONGO_DB || 'mcgrid';

if (!MONGO_URI) {
  console.error('❌ Missing MONGO_URI env var');
  process.exit(1);
}

// --- Connect to MongoDB ---
const client = new MongoClient(MONGO_URI);
await client.connect();
const db = client.db(MONGO_DB);

// Create some helpful indexes
await db.collection('huds').createIndex({ avatar_id: 1 }, { unique: true });
await db.collection('members').createIndex({ avatar_id: 1 }, { unique: true });
await db.collection('turf').createIndex({ beacon_id: 1 }, { unique: true });

const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex');
function verifySig(req, res, next) {
  const { payload, sig } = req.body || {};
  if (!payload || !sig) return res.status(400).send('Bad payload');
  const expect = sha1(SECRET + '|' + payload);
  if (expect !== sig) return res.status(401).send('Bad sig');
  try { req.data = JSON.parse(payload); } catch { return res.status(400).send('Bad JSON'); }
  next();
}

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

// --- API Endpoints ---

// HUD registration
app.post('/v1/hud/register', verifySig, async (req, res) => {
  const { avatar_id, avatar_name, url } = req.data;
  await db.collection('huds').updateOne(
    { avatar_id },
    { $set: { avatar_name: avatar_name || '', url: url || '', updated_at: Date.now() } },
    { upsert: true }
  );
  res.type('text/plain').send('OK');
});

// HUD heartbeat
app.post('/v1/hud/heartbeat', verifySig, async (req, res) => {
  const { avatar_id } = req.data;
  await db.collection('huds').updateOne(
    { avatar_id },
    { $set: { updated_at: Date.now() } }
  );
  res.type('text/plain').send('OK');
});

// List active HUD endpoints
app.get('/v1/hud/endpoints', async (req, res) => {
  const secret = req.get('x-auth');
  if (secret !== SECRET) return res.status(401).type('text/plain').send('No');
  const huds = await db.collection('huds')
    .find({ url: { $exists: true, $ne: '' } })
    .project({ _id: 0, avatar_id: 1, url: 1 })
    .toArray();
  res.type('text/plain').send(huds.map(h => `${h.avatar_id},${h.url}`).join('\\n'));
});

// Create a club
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

// Set member rank
app.post('/v1/member/set', verifySig, async (req, res) => {
  const { avatar_id, club_id, rank } = req.data;
  await db.collection('members').updateOne(
    { avatar_id },
    { $set: { club_id, rank: rank || 'Member' } },
    { upsert: true }
  );
  res.type('text/plain').send('OK');
});

// Update turf beacon
app.post('/v1/turf/update', verifySig, async (req, res) => {
  const { beacon_id, parcel, club_id, score } = req.data;
  await db.collection('turf').updateOne(
    { beacon_id },
    { $set: { parcel: parcel || '', club_id: club_id || '', score: parseInt(score || 0, 10), updated_at: Date.now() } },
    { upsert: true }
  );
  res.type('text/plain').send('OK');
});

// Show turf summary
app.get('/v1/turf/summary', async (req, res) => {
  const rows = await db.col
