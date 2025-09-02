import { Router } from 'express';
import {
  login,
  registerUser,
  logoutUser,
  currentUser,
  resendEmailVerification,
  verifyEmail,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changePassword,
} from '../controllers/auth.controller.js';
import { validate } from '../middleware/validator.middleware.js';
import {
  forgotPasswordValidator,
  passwordChangeValidator,
  registerValidator,
  resetForgotPasswordValidator,
  userLoginValidator,
} from '../validators/index.js';
import { verifyJWT } from '../middleware/auth.middleware.js';

const router = Router();

//unsecure routes
router.route('/register').post(registerValidator(), validate, registerUser);
router.route('/login').post(userLoginValidator(), validate, login);
router.route('/verify-email/:verificationToken').get(verifyEmail);
router.route('/refresh-token').post(refreshAccessToken);
router
  .route('/forgot-password')
  .post(forgotPasswordValidator(), validate, forgotPasswordRequest);
router
  .route('/reset-password/:resetToken')
  .post(resetForgotPasswordValidator(), validate, resetForgotPassword);

//secure routes
router.route('/logout').post(verifyJWT, logoutUser);
router.route('/current-user').post(verifyJWT, currentUser);
router
  .route('/change-password')
  .post(verifyJWT, passwordChangeValidator(), validate, changePassword);
router.route('/resend-email-verification').post(verifyJWT,resendEmailVerification)

export default router;
