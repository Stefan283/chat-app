var express = require('express');
var router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const { Users, Messages } = require('./Schema');

const accesExpire = '10s'

const verifyToken = (req, res, next) => {
    const header = req.headers['authorization'];
    const accessToken = header ? header.split(' ')[1] : null
    try {
        if (!accessToken) {
            return res.json({ success: false, message: 'Authentication required' });
        }
        jwt.verify(accessToken, process.env.ACCESS_TOKEN, async (err, decoded) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    const refreshToken = req.cookies.refreshToken
                    console.log(refreshToken)
                    if (!refreshToken) return res.json({ success: false, message: 'Refresh token missing', action: 'logout' })
                    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
                        if (err) return res.json({ success: false, message: 'Invalid refresh token', action: 'logout' })
                        const newAccessToken = jwt.sign({ username: user.username, avatar: user.avatar, email: user.email }, process.env.ACCESS_TOKEN, { expiresIn: accesExpire });
                        req.user = user
                        req.newAccessToken = newAccessToken
                    })
                } else {
                    return res.json({ success: false, message: 'Invalid access token', action: 'logout' });
                }
            } else {
                req.user = decoded;
            }
            next();
        });
    } catch (err) {
        console.log(err)
        return res.json({ succes: false, message: err.message })
    }
};



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

        const accessToken = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.ACCESS_TOKEN, { expiresIn: accesExpire });

        const refreshToken = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.REFRESH_TOKEN)

        const cookieOptions = {
            domain:'chat-drab-nine.vercel.app',
            secure: false,
            maxAge: 7 * 24 * 60 * 60,
            path:'/',
            httpOnly: false
        };
        const refreshTokenCookie = cookie.serialize('refreshToken', refreshToken, cookieOptions);

        res.setHeader('Set-Cookie', refreshTokenCookie);


        res.json({ success: true, accessToken: accessToken, user: user });
    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
});

router.post('/getuser', verifyToken, async (req, res) => {
    (req.newAccessToken)
    res.json({ success: true, user: req.user, newAccessToken: req.newAccessToken })
})

module.exports = router;
