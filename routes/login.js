var express = require('express');
var router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Users, Messages } = require('./Schema');

const verifyToken = (req, res, next) => {
    try {
        const accessToken = req.cookies.accessToken
        if (!accessToken) {
            return res.json({ success: false, message: 'Authentication required' });
        }

        jwt.verify(accessToken, process.env.ACCESS_TOKEN, async (err, decoded) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    const refreshTokenCookie = req.cookies.refreshToken
                    const username = jwt.decode(accessToken).username
                    const user = await Users.findOne({ username })
                    const refreshTokenDb = user?.refreshToken
                    if (!refreshTokenDb || !refreshTokenCookie) return res.json({ success: false, message: 'Refresh token missing', action: 'logout' })
                    if (refreshTokenCookie !== refreshTokenDb) {
                        return res.json({ success: false, message: 'Refresh token was changed', action: 'logout' })
                    }
                    jwt.verify(refreshTokenDb, process.env.REFRESH_TOKEN, (err, user) => {
                        if (err) return res.json({ success: false, message: 'Invalid refresh token', action: 'logout' })
                        const newJwt = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.ACCESS_TOKEN, { expiresIn: '30s' });
                        res.cookie('accessToken', newJwt, {
                            maxAge: 7 * 24 * 60 * 60 * 1000,
                            httpOnly: false,
                            sameSite: "None",
                            domain: "chat-drab-nine.vercel.app",
                            path: '/',
                            secure: true,
                        })
                        req.user = user
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

        const token = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.ACCESS_TOKEN, { expiresIn: '30s' });

        const refreshToken = jwt.sign({ username, avatar: user.avatar, email: user.email }, process.env.REFRESH_TOKEN)

        user.refreshToken = refreshToken
        await user.save()

        res.cookie('accessToken', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: false,
            sameSite: "None",
            domain: "chat-drab-nine.vercel.app",
            path: '/',
            secure: true,
        })


        res.cookie('refreshToken', refreshToken, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: false,
            sameSite: "None",
            domain: "chat-drab-nine.vercel.app",
            path: '/',
            secure: true,
        })

        res.json({ success: true, user: user });
    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
});

router.post('/logout', async (req, res) => {
    try {
        res.cookie('accessToken', null, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: false,
            sameSite: "None",
            domain: "chat-drab-nine.vercel.app",
            path: '/',
            secure: true,
        })

        res.cookie('refreshToken', null, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: false,
            sameSite: "None",
            domain: "chat-drab-nine.vercel.app",
            path: '/',
            secure: true,
        })

        res.json({ success: true })
    } catch (err) {
        console.log(err)
        res.json({ success: false, message: 'Unable to logout' })
    }
})

router.post('/getuser', verifyToken, async (req, res) => {
    res.json({ success: true, user: req.user })
})

module.exports = router;
