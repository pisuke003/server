import express from 'express';
import {
  login,
  logout,
  register,
  sendOtp,
  verifyEmail,
  resetPassword,
  resetOpt
} from '../controllers/authController.js'; 
import userAuth from '../middleware/authmiddle.js';

const authRouter = express.Router();

// Auth routes
authRouter.post('/register', register);
authRouter.post('/login', login); 
authRouter.post('/logout', logout);

// Email verification routes
authRouter.post('/send-verification-otp', userAuth, sendOtp);
authRouter.post('/verifyEmail', userAuth, verifyEmail);

// Password reset routes
authRouter.post('/request-password-reset', resetOpt);
authRouter.post('/reset-password', resetPassword);



export default authRouter;
