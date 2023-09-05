var express = require('express');
var router = express.Router();
const multer = require('multer');
const fs = require('fs');
const { S3 } = require('aws-sdk');

const upload = multer({ dest: 'uploads/' }); // Temporary storage for uploaded files



// Create an S3 client
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
  const stream = fs.createReadStream(photoPath);

  const params = {
    Bucket: 'chatapp2834',
    Key: `uploads/${req.file.originalname}`,
    Body: stream,
  };

  try {
    const uploaded = await s3.upload(params).promise();
    const photoUrl = uploaded.Location;

    // You can save the photoUrl to your database or send it back to the client
    res.status(200).send(photoUrl);
  } catch (error) {
    console.error('Error uploading to S3:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    // Clean up: Delete the temporary file
    fs.unlink(photoPath, (err) => {
      if (err) {
        console.error('Error deleting temporary file:', err);
      }
    });
  }
});

router.post('/upload-function', async (req, res) => {
  const { photo } = req.body
  try {
    console.log(photo)
    const url = await uploadPhoto(photo)
    if(url.success) {
      res.json({success:true, url: url.photo})
    } else {
      res.json({success:false, message: url.message})
    }
  } catch (err) {
    res.json({success:false})
  }
})


const uploadPhoto = async (photoData) => {
  try {
    const buffer = Buffer.from(photoData, 'base64');
    const fileName = `uploads/${Date.now()}${Math.random()}`;
    const params = {
      Bucket: 'chatapp2834',
      Key: fileName,
      Body: buffer,
    };

    const uploaded = await s3.upload(params).promise();
    const photoUrl = uploaded.Location;
    console.log('Photo uploaded succesfuly')
    return { success: true, photo: photoUrl };
  } catch (error) {
    console.error('Error uploading to S3:', error);
    return { success: false, message: error.message }
  }
};






module.exports = router;
