const express = require('express');
const router = express.Router();

const UserController = require('../controllers/user_controller.js');
router.post('/signup', UserController.signup);
router.get('/verify/:token', UserController.verify);
router.get('/verifyLogin/:token', UserController.verifyLogin);
router.post('/signin', UserController.signin);
router.get('/', UserController.home);
router.post('/logout/:id', UserController.logout);
router.post('/forgotPassword/:id', UserController.forgotPassword);
router.get('/resetPassword/:id/:verificationToken', UserController.resetPassword);
router.post('/resetPassword/:id/:verificationToken', UserController.resetPasswordPost);

module.exports = router;