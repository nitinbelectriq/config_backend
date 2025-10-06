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



// ---------------- Signup ----------------
export async function signup(req, res) {
  const { email, password, name, mobile, macid } = req.body; 
debugger;
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

    const verify_link = `http://54.242.254.40/auth/verify?code=${verification_code}`;
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
  debugger;
  const { email, password, EngineeringModeLogin } = req.body;
  const engineeringMode = !!EngineeringModeLogin;

  if (!email || !password) {
    return res.status(400).json({ status: false, message: 'Email and password are required' });
  }

  try {
    // Determine table to check
    const table = engineeringMode ? 'Engineeringmodelogin' : 'users';

    // Check if user exists in the selected table
    const [rows] = await pool.query(`SELECT * FROM ${table} WHERE email = ?`, [email]);
    if (!rows.length) {
      if (engineeringMode) {
        return res.status(404).json({
          status: false,
          message: 'Engineering mode user not found in Engineeringmodelogin table'
        });
      } else {
        return res.status(401).json({ status: false, message: 'Invalid credentials' });
      }
    }

    const user = rows[0];

    // Compare password
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ status: false, message: 'Invalid credentials' });

    // For normal users, check email verification
    if (!engineeringMode && user.is_verified !== 1) {
      return res.status(403).json({ status: false, message: 'Please verify your email' });
    }

    // Generate JWT
    const token = signToken({ sub: user.id, email: user.email });

    // Update token in DB
    await pool.query(`UPDATE ${table} SET token=? WHERE id=?`, [token, user.id]);

    // Response
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

    const pin = generatePinrandom();
    await pool.query(`UPDATE ${table} SET token = ? WHERE email = ?`, [pin, email]);

    await sendEmail(email, 'Password Reset Code', `Your password reset code is: ${pin}\n\nDo not share this with anyone.`);
    res.json({ status: true, message: 'OTP sent to your email' });
  } catch (err) {
    console.error('requestReset error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

function generatePinrandom() {
  // Generates a 6-digit numeric PIN
  return Math.floor(100000 + Math.random() * 900000).toString();
}
// ---------------- Validate PIN ----------------
export async function validatePin(req, res) {
  const { email, pin } = req.body;

  if (!email || !pin) {
    return res.status(400).json({ status: false, message: 'Missing email or PIN' });
  }

  try {
    // Fetch the latest PIN for the email
    const [rows] = await pool.query(
      'SELECT pin, created_at FROM engineering_pins WHERE email = ?',
      [email]
    );

    if (!rows.length) {
      return res.json({ status: false, message: 'Email not found' });
    }

    const { pin: dbPin, created_at } = rows[0];
    const createdAtTime = new Date(created_at).getTime();
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (pin === dbPin && (now - createdAtTime <= fiveMinutes)) {
      // Clear the PIN after successful verification
      await pool.query('UPDATE engineering_pins SET pin = NULL WHERE email = ?', [email]);
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
  const { token, newPassword, EngineeringModeLogin } = req.body;
  const engineeringMode = !!EngineeringModeLogin;

  if (!token || !newPassword) {
    return res.status(400).json({ status: false, message: 'Missing token or new password' });
  }

  try {
    // Choose table dynamically
    const table = engineeringMode ? 'Engineeringmodelogin' : 'users';

    // Hash new password
    const hash = await bcrypt.hash(newPassword, 12);

    // Update password where token matches and clear the token
    const [result] = await pool.query(
      `UPDATE ${table} SET password = ?, token = NULL WHERE token = ?`,
      [hash, token]
    );

    if (result.affectedRows > 0) {
      return res.json({ status: true, message: 'Password updated successfully' });
    } else {
      return res.status(400).json({ status: false, message: 'Invalid token or token expired' });
    }

  } catch (err) {
    console.error('updatePassword error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}


// ---------------- Generate PIN (demo only) ----------------
export async function generatePin(req, res) {
  const { email, name, mobile, useremail } = req.body;

  if (!email) {
    return res.status(400).json({ status: false, message: 'Email is required' });
  }

  try {
    // Check if email exists in mngremails
    const [rows] = await pool.query('SELECT id FROM mngremails WHERE email = ?', [email]);
    if (!rows.length) {
      return res.json({ status: false, message: 'Email not registered' });
    }

    // Generate 6-digit numeric PIN
    const pin = generateSecurePin(6);

    // Insert or replace PIN in engineering_pins table
    await pool.query(
      `REPLACE INTO engineering_pins (email, pin, created_at) VALUES (?, ?, NOW())`,
      [email, pin]
    );

    // Prepare email content
    const subject = 'Engineering Mode PIN';
    const message = `Dear Sir,

I have requested a pin to configure the charger. My details are:
Name: ${name || ''}
Mobile: ${mobile || ''}
Email: ${useremail || ''}

OTP to access Engineering Mode is: ${pin}
This code is valid for 5 minutes.

Regards,
BelectriQ Team`;

    // Send email
    const sent = await sendEmail(email, subject, message);

    if (sent) {
      res.json({ status: true, message: 'OTP sent to your registered email' });
    } else {
      res.json({ status: false, message: 'Failed to send email' });
    }

  } catch (err) {
    console.error('generatePin error:', err);
    res.status(500).json({ status: false, message: 'Server error' });
  }
}

