import express from 'express';
import {
  signup,
  login,
  verify,
  requestReset,
  validatePin,
  updatePassword,
  generatePin
} from '../controllers/authController.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// Public routes
router.post('/signup', signup);
router.post('/login', login);
router.get('/verify', verify); // token not needed in header
router.post('/request-reset', requestReset); // email in body

// Protected routes (JWT required)
router.post('/validate-pin', requireAuth, validatePin);
router.post('/update-password', requireAuth, updatePassword);
router.post('/generate-pin', requireAuth, generatePin);

export default router;
