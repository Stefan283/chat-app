var express = require('express');
var router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Users, Messages } = require('./Schema');
const accessExpire = '10s'

router.post('/register', async (req, res) => {
    const { username, password, email, avatar } = req.body;
    try {
        const userDb = await Users.findOne({ username })
        const emailDb = await Users.findOne({ email })
        if (userDb || emailDb) {
            res.json({ success: false, message: 'User or Email already exist' })
        } else {
            const newMessgaes = new Messages({
                email: email,
                conversation: []
            })
            await newMessgaes.save()
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new Users({
                username: username,
                email: email,
                avatar: avatar,
                password: hashedPassword,
                avatar: '',
                posts: []
            });
            newUser.save()
            res.json({ success: true, message: 'User registered successfully.' });
        }
    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
});


router.post('/login', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        const user = await Users.findOne({ username, email })
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success: false, message: 'Authentification failed!' })
        }


        const accessToken = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.ACCESS_TOKEN, { expiresIn: accessExpire });

        const refreshToken = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.REFRESH_TOKEN)

        res.json({ success: true, accessToken: accessToken, refreshToken: refreshToken, user: user });
    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
});

module.exports = router;
