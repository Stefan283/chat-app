const mongoose = require('mongoose')

const usersSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  avatar: String,
  refreshToken: String,
  posts: [{
    src: String,
    image: String,
    email: String,
    message: String,
    _id: {
      $oid: String
    },
    likes: [String],
    comments: [{
      date: String,
      email: String,
      message: String,
      image: String
    }]
  }]
});


const messagesSchema = new mongoose.Schema({
  email: String,
  conversations: [{
    email: String,
    bg: String,
    username: String,
    seen: Boolean,
    avatar: String,
    messages: [{
      email: String,
      date: Number,
      message: String,
      photo: String
    }]
  }]
})

const Users = mongoose.model('users', usersSchema);
const Messages = mongoose.model('messages', messagesSchema)


module.exports = {
  Users,
  Messages
}