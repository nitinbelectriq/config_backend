export async function getFileUrl(req, res) {
  // If you use signed URLs, implement generation here; otherwise return path
  const { filename } = req.query;
  if (!filename) return res.status(400).json({ message: 'Missing filename' });
  // Example: return a sanitized path (ensure validation to prevent path traversal)
  return res.json({ url: `/uploads/${encodeURIComponent(filename)}` });
}
