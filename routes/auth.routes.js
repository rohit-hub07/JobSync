const express = require('express');
const {
  registerUserController,
  verificationController,
  loginController,
  logoutController,
  profileController,
  forgetPasswordController,
  resetPasswordController,
  resendVerificationController,
  dashboardController,
} = require('../controllers/auth.controller.js');
const {
  authenticateToken,
  requireVerification,
  redirectIfAuthenticated,
  optionalAuth,
} = require('../middleware/auth.middleware.js');

const authRouter = express.Router();

// Public routes (redirect to dashboard if already authenticated)
authRouter.get('/login', redirectIfAuthenticated, (req, res) => {
  res.render('login.ejs');
});

authRouter.get('/signup', redirectIfAuthenticated, (req, res) => {
  res.render('signup.ejs');
});

// Auth actions
authRouter.post('/signup', registerUserController);
authRouter.post('/login', loginController);
authRouter.get('/auth/verify/:token', verificationController);
authRouter.post('/forgot-password', forgetPasswordController);

// Reset password routes
authRouter.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  res.render('reset-password.ejs', { token });
});

authRouter.post('/reset-password/:token', resetPasswordController);

// Protected routes (require authentication)
authRouter.get('/dashboard', authenticateToken, async (req, res) => {
  res.send("Coming soon!");
});
authRouter.get('/profile', authenticateToken, profileController);
authRouter.post('/logout', authenticateToken, logoutController);
authRouter.post('/resend-verification', authenticateToken, resendVerificationController);



module.exports = authRouter;
