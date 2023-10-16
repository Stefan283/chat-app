var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
require('dotenv').config()
const jwt = require('jsonwebtoken');
const cors = require('cors')

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const loginRouter = require('./routes/login')

const schema = require('./routes/graphql')
const { graphqlHTTP } = require('express-graphql');


var app = express();


app.use(cookieParser());
app.use(function (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', process.env.WEBSITE);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', true);
  next();
});


app.use(cors({
  origin: process.env.WEBSITE,
  credentials: true,
}));


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function verifyAccessToken(req, res, next) {
  try {
    const header = req.headers['authorization'];
    const token = header ? header.split(' ')[1] : null
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access token is missing' });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      req.user = decoded;
      next();
    });
  } catch (err) {
    console.log(err)
    return res.status(401).json({ success: false, message: err.message })
  }
}



app.use('/', indexRouter);
app.use('/users', verifyAccessToken, usersRouter);
app.use('/login', loginRouter)
app.use(
  '/graphql',
  verifyAccessToken,
  graphqlHTTP({
    schema,
    graphiql: true,
  })
);


// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
