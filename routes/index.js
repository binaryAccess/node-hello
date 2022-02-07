const express = require('express');
const router = express.Router();
const path = require('path');
const AuthMiddleware = require('../middleware/AuthMiddleware');
const JWTHelper = require('../helpers/JWTHelper');
const DBHelper = require('../helpers/DBHelper');

router.get('/', AuthMiddleware, async (req, res, next) => {
    try {
        let user = await DBHelper.getUser(req.data.username);

        if (user === undefined) {
            return res.send(`user ${req.data.username} doesn't exist in our database.`);
        }

        return res.render('index.html', { user });
    } catch (err) {
        return next(err);
    }
});

router.get('/auth', (req, res) => 
    res.render('auth.html', { query: req.query }));

router.get('/logout', (req, res) => {
    res.clearCookie('session');
    return res.redirect('/auth');
});

router.post('/auth', async (req, res) => {
    const { username, password } = req.body;

    if ((username !== undefined && username.trim().length === 0) || (password !== undefined && password.trim().length === 0)){
        return res.redirect('/auth');
    }

    if (req.body.register !== undefined) {
        let user = await DBHelper.getUser(username);

        if (user !== undefined) {
            return res.redirect('/auth?error=Username already exists');
        }
        
        DBHelper.createUser(username, password);
        return res.redirect('/auth?error=Registered successfully&type=success');
    }

    let login_result = await DBHelper.attemptLogin(username, password);

    if (!login_result) {
        return res.redirect('/auth?error=Invalid username or password');
    }

    let token = await JWTHelper.sign({
        username: username.replace(/'/g, "\'\'").replace(/"/g, "\"\"")
    })

    res.cookie('session', token, { maxAge: 900000 });
    return res.redirect('/');
});

module.exports = router;