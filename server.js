import express from 'express';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// ESM import for pool
import { pool } from './db.js';

// Import routes
import authRoutes from './routes/auth.js';
import filesRoutes from './routes/files.js';

const app = express();

// Security middlewares
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '10kb' }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use(limiter);

app.set('trust proxy', 1);

app.use('/auth', authRoutes);
app.use('/files', filesRoutes);

app.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS solution');
    res.json({ ok: true, data: rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server listening on port ${PORT}`));
