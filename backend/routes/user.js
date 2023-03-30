const express = require('express');
const router = express.Router();

const auth = require('../middleware/auth');

const userCtrl = require('../controllers/user');

router.post('/signup', userCtrl.signUp);
router.post('/login', auth, userCtrl.login);

module.exports = router;