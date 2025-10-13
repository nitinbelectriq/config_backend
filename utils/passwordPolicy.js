// utils/passwordPolicy.js
import bcrypt from 'bcrypt';

const MIN_LENGTH = 8;
const PASSWORD_HISTORY_LIMIT = 3; // last 3 passwords can't be reused

export function validatePasswordPolicy(password) {
  if (!password || password.length < MIN_LENGTH) {
    return { valid: false, message: `Password must be at least ${MIN_LENGTH} characters long.` };
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { valid: false, message: 'Password must contain uppercase, lowercase, number, and special character.' };
  }
  return { valid: true };
}

// Updated: allow custom table name for Engineeringmode
export async function checkPasswordReuse(userId, newPassword, pool, tableName = 'password_history') {
  const [history] = await pool.query(
    `SELECT password_hash FROM ${tableName} WHERE user_id = ? ORDER BY changed_at DESC LIMIT ?`,
    [userId, PASSWORD_HISTORY_LIMIT]
  );
  for (const row of history) {
    const match = await bcrypt.compare(newPassword, row.password_hash);
    if (match) return true;
  }
  return false;
}
