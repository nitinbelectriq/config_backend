import { pool } from '../db.js';

export async function getFileUrl(req, res) {
  try {
    // Accept version from query or body
    const version = req.query.version || req.body.version;

    // Validate
    if (!version || version.trim() === '') {
      return res.status(400).json({ success: false, message: 'Firmware version is required.' });
    }

    // Query database
    const [rows] = await pool.query('SELECT url FROM files WHERE version = ?', [version.trim()]);

    if (rows.length > 0) {
      // Found
      return res.json({ success: true, url: rows[0].url });
    } else {
      // Not found
      return res.json({ success: false, message: 'Version not found.' });
    }
  } catch (err) {
    console.error('Error in getFileUrl:', err);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
}
