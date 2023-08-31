var express = require('express');
var router = express.Router();
const { Users, Messages } = require("./Schema")

router.route('/')
  .get(function (req, res, next) {
    try {
      res.json({ success: true })
    } catch (err) {
      res.json({ success: false, message: err });
    }
  })
  .post(async (req, res) => {
    const { email, name, image } = req.body
    try {
      const user = await Users.find({ email })
      if (user.length > 0) {
        res.json({ success: true })
      } else {
        const newUser = new Users({
          email: email,
          name: name,
          avatar: image
        })
        await newUser.save()
        const newMessgaes = new Messages({
          email: email,
          conversation: []
        })
        await newMessgaes.save()
        res.json({ success: true })
      }
    } catch (err) {
      console.error(err)
      res.json({ success: false, message: err })
    }
  })

router.post('/posts', async (req, res) => {
  const email = 'iosifs617@gmail.com'
  const newPost = {
    src: '',
    image: '',
    email: 'iosifs617@gmail.com',
    message: 'gela gela ce chiloti are pe ea',
    likes: [],
    comments: [],
  }
  try {
    const user = await Users.findOne({ email })
    console.log(user.posts)
    user.posts = [...user.posts, newPost]
    await user.save()
    res.json({ success: true })
  } catch (err) {
    console.log(err)
    res.json({ success: false, message: err })
  }
})

router.post('/profile', async (req, res) => {
  const { email } = req.body
  try {
    const user = await Users.findOne({ email })
    if (user) {
      res.json({ success: true, message: user })
    } else {
      res.json({ success: false, message: 'User not found' })
    }
  } catch (err) {
    res.json({ success: false, message: err })
  }
})

router.patch('/posts', async (req, res) => {
  const { email, date, image, message, id, photoEmail } = req.body
  try {
    const comment = { email, date, message, image }
    const user = await Users.findOne({ email: photoEmail });
    const postIndex = user.posts.findIndex(post => post._id.$oid === id.$oid);
    user.posts[postIndex].comments.push(comment);
    await user.save();
    res.json({ success: true })
  } catch (err) {
    console.log(err)
    res.json({ success: false, message: err })
  }
})

router.post(`/posts/like`, async (req, res) => {
  const { value, user, userPost, id } = req.body
  try {
    const userDb = await Users.findOne({ email: userPost })
    const postIndex = userDb.posts.findIndex(post => post._id.$oid === id.$oid);
    console.log(postIndex)
    if (value) {
      userDb.posts[postIndex].likes.push(user)
      await userDb.save()
    } else {
      userDb.posts[postIndex].likes.splice(user, 1);
      await userDb.save()
    }
    console.log(user)
    res.json({ success: true })
  } catch (err) {
    res.json({ success: false })
  }
})

module.exports = router;
