var express = require('express');
var router = express.Router();
const multer = require('multer');
const fs = require('fs');
const { S3 } = require('aws-sdk');

const upload = multer({ dest: 'uploads/' }); // Temporary storage for uploaded files



const s3 = new S3({
  region: 'eu-west-3',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCEsS_KEY,
  },
});

router.post('/upload-photo', upload.single('photo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No photo provided' });
  }

  const photoPath = req.file.path;
  console.log(photoPath)
  const stream = fs.createReadStream(photoPath);

  const params = {
    Bucket: 'chatapp2834',
    Key: `uploads/${req.file.originalname}${Math.random()}`,
    Body: stream,
  };
  
  try {
    const uploaded = await s3.upload(params).promise();
    const photoUrl = uploaded.Location;

    res.status(200).send({ success: true, url: photoUrl });
  } catch (error) {
    console.error('Error uploading to S3:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    fs.unlink(photoPath, (err) => {
      if (err) {
        console.error('Error deleting temporary file:', err);
      }
    });
  }
});


module.exports = router;
