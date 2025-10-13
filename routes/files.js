import express from 'express';
import { getFileUrl } from '../controllers/filesController.js';
import { requireAuth } from '../middleware/auth.js';
const router = express.Router();
router.get('/url',requireAuth, getFileUrl);
export default router;
