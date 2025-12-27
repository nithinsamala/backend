const express = require("express");
const multer = require("multer");
const path = require("path");
const UploadedFile = require("./models/UploadedFile");
const { checkToken } = require("./authMiddleware"); // or export it

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() + "-" + Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Only PDF files allowed"));
    }
    cb(null, true);
  }
});

router.post(
  "/",
  checkToken,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const file = await UploadedFile.create({
        filename: req.file.filename,
        originalName: req.file.originalname,
        uploadedBy: req.userId
      });

      res.json({
        success: true,
        file
      });
    } catch (err) {
      console.error("Upload error:", err);
      res.status(500).json({ message: "Upload failed" });
    }
  }
);

module.exports = router;
