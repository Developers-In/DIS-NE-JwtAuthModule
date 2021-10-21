const express = require('express');
const router = express.Router();

const UserController = require('../controllers/user_controller.js');
router.post('/signup', UserController.signup);

module.exports = router;