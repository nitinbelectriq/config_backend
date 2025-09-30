import { pool } from '../db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { sendEmail } from '../utils/mailer.js';
import { generateSecurePin } from '../utils/cryptoUtils.js';

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Helper: create JWT
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function generatePin() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------------- Signup ----------------
export async function signup(req, res) {
  const { email, password, name, mobile, macid } = req.body; 

  if (!email || !password || !name || !mobile) {
    return res.status(400).json({ status: false, message: 'Missing required fields' });
  }

  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ status: false, message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verification_code = crypto.createHash('md5').update(crypto.randomUUID() + email).digest('hex');

    await pool.query(
      `INSERT INTO users 
      (email, password, is_verified, verification_code, name, mobile, macid) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, hashedPassword, 0, verification_code, name, mobile, macid || null]
    );

    const verify_link = `http://3.91.159.64/verify?code=${verification_code}`;
    const message = `Hello ${name},\n\nPlease click the following link to verify your email:\n\n${verify_link}\n\nThank you!`;

    const sent = await sendEmail(email, 'BelectriQ Mobility Email Confirmation', message);

    if (sent) {
      res.json({ status: true, message: 'Signup successful! Check your email to verify.' });
    } else {
      res.json({ status: false, message: 'Signup saved, but email failed to send.' });
    }

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

// ---------------- Login ----------------
export async function login(req, res) {
  const { email, password, EngineeringModeLogin } = req.body;
  const engineeringMode = !!EngineeringModeLogin;

  if (!email || !password) {
    return res.status(400).json({ status: false, message: 'Email and password are required' });
  }

  try {
    const table = engineeringMode ? 'Engineeringmodelogin' : 'users';
    const [rows] = await pool.query(`SELECT * FROM ${table} WHERE email=?`, [email]);
    if (!rows.length) return res.status(401).json({ status: false, message: 'Invalid credentials' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ status: false, message: 'Invalid credentials' });

    if (!engineeringMode && user.is_verified !== 1) {
      return res.status(403).json({ status: false, message: 'Please verify your email' });
    }

    const token = signToken({ sub: user.id, email: user.email });
    await pool.query(`UPDATE ${table} SET token=? WHERE id=?`, [token, user.id]);

    res.json({
      status: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name || '',
        mobile: user.mobile || '',
        macid: user.macid || '',
        EngineeringMode: engineeringMode,
        token
      }
    });

  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

// ---------------- Verify ----------------
export async function verify(req, res) {
  const { code } = req.query;
  if (!code) return res.status(400).send('❌ Verification code missing');

  try {
    const [result] = await pool.query(
      'UPDATE users SET is_verified = 1 WHERE verification_code = ?',
      [code]
    );
    if (result.affectedRows > 0) res.send('✅ Your email has been verified.');
    else res.send('❌ Invalid or expired verification code.');
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).send('❌ Server error');
  }
}

// ---------------- Request Reset ----------------
export async function requestReset(req, res) {
  const { email, EngineeringModeLogin } = req.body;
  const engineeringMode = !!EngineeringModeLogin;
  if (!email) return res.status(400).json({ status: false, message: 'Missing email' });

  try {
    const table = engineeringMode ? 'Engineeringmodelogin' : 'users';
    const [rows] = await pool.query(`SELECT id FROM ${table} WHERE email = ?`, [email]);
    if (!rows.length) return res.json({ status: false, message: 'Email not found' });

    const pin = generatePin();
    await pool.query(`UPDATE ${table} SET token = ? WHERE email = ?`, [pin, email]);

    await sendEmail(email, 'Password Reset Code', `Your password reset code is: ${pin}\n\nDo not share this with anyone.`);
    res.json({ status: true, message: 'OTP sent to your email' });
  } catch (err) {
    console.error('requestReset error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

// ---------------- Validate PIN ----------------
export async function validatePin(req, res) {
  const { pin, EngineeringModeLogin } = req.body;
  const userId = req.user.sub;
  const engineeringMode = !!EngineeringModeLogin;

  try {
    const table = engineeringMode ? 'Engineeringmodelogin' : 'users';
    const [rows] = await pool.query(`SELECT id, token, updated_at FROM ${table} WHERE id = ?`, [userId]);
    if (!rows.length) return res.json({ status: false, message: 'User not found' });

    const user = rows[0];
    const tokenTime = user.updated_at ? new Date(user.updated_at).getTime() : null;
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (user.token === pin && (!tokenTime || now - tokenTime <= fiveMinutes)) {
      await pool.query(`UPDATE ${table} SET token = NULL WHERE id = ?`, [user.id]);
      return res.json({ status: true, message: 'PIN verified successfully' });
    } else {
      return res.json({ status: false, message: 'Invalid or expired PIN' });
    }
  } catch (err) {
    console.error('validatePin error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

// ---------------- Update Password ----------------
export async function updatePassword(req, res) {
  const { newPassword } = req.body;
  const userId = req.user.sub;

  if (!newPassword) return res.status(400).json({ message: 'Missing new password' });

  try {
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password=? WHERE id=?', [hash, userId]);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('updatePassword error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ---------------- Generate PIN (demo only) ----------------
export async function generatePin(req, res) {
  try {
    const pin = generateSecurePin(6);
    res.json({ message: 'PIN generated', pin });
  } catch (err) {
    console.error('generatePin error', err);
    res.status(500).json({ error: 'Server error' });
  }
}
