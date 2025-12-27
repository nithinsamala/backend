const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, "uploads");

/* =========================
   SCHEMA (FIXED)
========================= */
const uploadedFileSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

const UploadedFile =
  mongoose.models.UploadedFile ||
  mongoose.model("UploadedFile", uploadedFileSchema);

/* =========================
   AUTH (SAFE)
========================= */
const auth = (req, res, next) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error("Auth error:", err.message);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   MULTER (PDF ONLY)
========================= */
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() +
      "-" +
      Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);

    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Only PDF files are allowed"));
    }
    cb(null, true);
  }
});

/* =========================
   ROUTES (FIXED)
========================= */
router.post("/", auth, upload.single("file"), async (req, res) => {
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
});

module.exports = router;
