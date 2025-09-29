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

router.post('/signup', signup);
router.post('/login', login);
router.post('/verify',requireAuth, verify);
router.post('/request-reset',requireAuth, requestReset);
router.post('/validate-pin',requireAuth, validatePin);
router.post('/update-password',requireAuth, updatePassword);
router.post('/generate-pin',requireAuth, generatePin);

export default router;
