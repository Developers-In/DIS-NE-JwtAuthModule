const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middlewares/VerifyToken.js')

const UserController = require('../controllers/user_controller.js');
router.post('/signup', UserController.signup);
router.get('/verifySignUp/:verificationToken', UserController.verifySignUp);
router.get('/verifySignin/:verificationToken', UserController.verifySignIn);
router.post('/signin', UserController.signin);
router.post('/forgotPassword/:userId', UserController.forgotPassword);
router.get('/resetPassword/:userId/:verificationToken', UserController.resetPassword);
router.post('/resetPassword/:userId/:verificationToken', UserController.resetPasswordPost);
router.get('/requestVerification/:userId', UserController.resendVerificationToken);
router.get('/:userId/users', verifyToken, UserController.getAllUsers);
router.post('/refresh',  UserController.createRefreshToken);

module.exports = router;