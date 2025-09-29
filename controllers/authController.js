import { pool } from '../db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { sendEmail } from '../utils/mailer.js';
import { generateSecurePin } from '../utils/cryptoUtils.js';

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Helper: create token without storing secrets in plain memory
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export async function signup(req, res) {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Missing fields' });
  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
    if (existing.length) return res.status(409).json({ message: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (email,password,created_at) VALUES (?,?,NOW())', [email, hash]);
    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('signup error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function login(req, res) {
  debugger;
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Missing credentials' });
  try {
    const [rows] = await pool.query('SELECT id,email,password FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(401).json({ message: 'Invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    // create JWT with only necessary info
    const token = signToken({ sub: user.id, email: user.email });
    res.json({ message: 'Login success', token });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function verify(req, res) {
  // Implement verification logic, e.g., email verify token
  res.json({ message: 'Verify endpoint - implement as needed' });
}

export async function requestReset(req, res) {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Missing email' });
  try {
    // generate a secure 6-digit PIN
    const pin = generateSecurePin(6);
    // store pin hashed in DB with expiry (example TTL 15 minutes)
    const pinHash = crypto.createHash('sha256').update(pin).digest('hex');
    await pool.query('INSERT INTO password_reset (email,pin_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(), INTERVAL 15 MINUTE))', [email, pinHash]);
    // send pin via email (don't include PIN in logs)
    await sendEmail(email, 'Password reset PIN', `Your PIN is: ${pin}`);
    res.json({ message: 'Reset PIN sent (if email exists)' });
  } catch (err) {
    console.error('requestReset error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function validatePin(req, res) {
  const { email, pin } = req.body;
  if (!email || !pin) return res.status(400).json({ message: 'Missing fields' });
  try {
    const pinHash = crypto.createHash('sha256').update(pin).digest('hex');
    const [rows] = await pool.query('SELECT * FROM password_reset WHERE email=? AND pin_hash=? AND expires_at > NOW() ORDER BY id DESC LIMIT 1', [email, pinHash]);
    if (!rows.length) return res.status(400).json({ valid: false, message: 'Invalid or expired PIN' });
    res.json({ valid: true });
  } catch (err) {
    console.error('validatePin error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function updatePassword(req, res) {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) return res.status(400).json({ message: 'Missing fields' });
  try {
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password=? WHERE email=?', [hash, email]);
    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error('updatePassword error', err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function generatePin(req, res) {
  try {
    const pin = generateSecurePin(6);
    // Do not send PIN in logs. Caller should provide delivery target (email/phone)
    res.json({ message: 'PIN generated', pin }); // in real systems, do NOT return PIN - this is for demo only
  } catch (err) {
    console.error('generatePin error', err);
    res.status(500).json({ error: 'Server error' });
  }
}
