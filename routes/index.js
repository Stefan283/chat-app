var express = require('express');
var router = express.Router();
const { Users } = require('./Schema')
 


router.post('/', async function (req, res, next) {
  try {
    res.json({ success: true })
  } catch (err) {
    console.log(err)
    res.json({ success: false, message: err })
  }
});








module.exports = router;
