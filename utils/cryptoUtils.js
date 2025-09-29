import crypto from 'crypto';

// Generate a secure numeric PIN of length n (digits)
export function generateSecurePin(length = 6) {
  if (length <= 0) return '';
  // generate enough random bytes, then map to digits
  const bytes = crypto.randomBytes(length);
  let pin = '';
  for (let i = 0; i < length; i++) {
    pin += (bytes[i] % 10).toString();
  }
  return pin;
}

// AES-GCM helper (returns base64 ciphertext and iv)
export function aesGcmEncrypt(plainText, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64')
  };
}

export function aesGcmDecrypt(ciphertextB64, key, ivB64, tagB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const encrypted = Buffer.from(ciphertextB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}
