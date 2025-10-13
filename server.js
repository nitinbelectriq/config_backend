import express from 'express';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// Database connection (ensure pool is properly exported from db.js)
import { pool } from './db.js';

// Import route modules
import authRoutes from './routes/auth.js';
import filesRoutes from './routes/files.js';

const app = express();
app.disable('x-powered-by');
// ✅ Security middlewares
app.use(helmet());
app.use(cors({ origin: '*' })); // You can restrict origin in production
app.use(bodyParser.json({ limit: '10kb' }));

// ✅ Rate limiting (60 requests per minute per IP)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// ✅ Trust proxy (for correct IP logging / HTTPS setups)
app.set('trust proxy', 1);

// ✅ Routes
app.use('/auth', authRoutes);
app.use('/files', filesRoutes);

// ✅ Test route to confirm DB connectivity
app.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS solution');
    res.json({ ok: true, data: rows });
  } catch (err) {
    console.error('DB Error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
