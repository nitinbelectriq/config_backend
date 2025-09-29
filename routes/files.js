import express from 'express';
import { getFileUrl } from '../controllers/filesController.js';
const router = express.Router();
router.get('/url', getFileUrl);
export default router;
