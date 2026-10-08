import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoose from 'mongoose';
import Scan from './models/Scan.js';
import { analyzeMessage, analyzeUrl } from './analysis.js';

const app = express();
const port = Number(process.env.PORT || 8080);
const origins = (process.env.CLIENT_ORIGINS || 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || origins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS'));
  }
}));
app.use(express.json({ limit: '16kb' }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false }));

function requireClientId(req, res, next) {
  const clientId = req.get('x-client-id');
  if (typeof clientId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clientId)) {
    return res.status(400).json({ error: 'A valid client ID is required.' });
  }
  req.clientId = clientId;
  return next();
}

function requireText(field, maxLength) {
  return (req, res, next) => {
    const value = req.body?.[field];
    if (typeof value !== 'string' || value.trim().length === 0) {
      return res.status(400).json({ error: `${field} must be a non-empty string.` });
    }
    if (value.length > maxLength) {
      return res.status(413).json({ error: `${field} must be at most ${maxLength} characters.` });
    }
    req.scanInput = value.trim();
    return next();
  };
}

async function saveScan(clientId, inputType, result) {
  await Scan.create({
    clientId,
    inputType,
    riskScore: result.score,
    riskLevel: result.riskLevel,
    threatType: result.threatType
  });
}

app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.post('/api/analyze/message', requireClientId, requireText('message', 10_000), async (req, res, next) => {
  try {
    const result = analyzeMessage(req.scanInput);
    await saveScan(req.clientId, 'Message', result);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

app.post('/api/analyze/url', requireClientId, requireText('url', 2_048), async (req, res, next) => {
  try {
    const result = analyzeUrl(req.scanInput);
    await saveScan(req.clientId, 'URL', result);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

app.get('/api/history', requireClientId, async (req, res, next) => {
  try {
    const [scans, groupedTotals] = await Promise.all([
      Scan.find({ clientId: req.clientId })
        .sort({ createdAt: -1 })
        .limit(100)
        .select('inputType riskScore riskLevel threatType createdAt')
        .lean(),
      Scan.aggregate([
        { $match: { clientId: req.clientId } },
        { $group: { _id: '$riskLevel', count: { $sum: 1 } } }
      ])
    ]);

    const totals = { total: 0, safe: 0, suspicious: 0, highRisk: 0 };
    for (const group of groupedTotals) {
      totals.total += group.count;
      if (group._id === 'SAFE') totals.safe = group.count;
      if (group._id === 'SUSPICIOUS') totals.suspicious = group.count;
      if (group._id === 'HIGH RISK') totals.highRisk = group.count;
    }

    return res.json({
      totals,
      scans: scans.map((scan) => ({
        inputType: scan.inputType,
        riskScore: scan.riskScore,
        riskLevel: scan.riskLevel,
        threatType: scan.threatType,
        createdAt: scan.createdAt
      }))
    });
  } catch (error) {
    return next(error);
  }
});

app.delete('/api/history', requireClientId, async (req, res, next) => {
  try {
    await Scan.deleteMany({ clientId: req.clientId });
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.message === 'Origin is not allowed by CORS') {
    return res.status(403).json({ error: 'This website is not allowed to call the API.' });
  }
  if (error.status === 400 || error.status === 413) {
    return res.status(error.status).json({ error: error.status === 413 ? 'Request body is too large.' : 'Request body must be valid JSON.' });
  }
  console.error('API request failed:', error);
  return res.status(500).json({ error: 'The server could not complete the request.' });
});

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI must be set.');
  await mongoose.connect(process.env.MONGODB_URI);
  app.listen(port, '0.0.0.0', () => {
    console.log(`ScamShield API listening on port ${port}`);
  });
}

start().catch((error) => {
  console.error('Could not start ScamShield API:', error.message);
  process.exitCode = 1;
});
