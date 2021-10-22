const express = require('express');
const router = express.Router();

const UserController = require('../controllers/user_controller.js');
router.post('/signup', UserController.signup);
router.get('/verify/:token', UserController.verify);
router.post('/signin', UserController.signin);

module.exports = router;