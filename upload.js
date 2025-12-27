// upload.js
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const router = express.Router();

/* =========================
   UPLOAD DIRECTORY (FIXED)
========================= */
const UPLOAD_DIR = path.join(process.cwd(), "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* =========================
   SCHEMA
========================= */
const uploadedFileSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  uploadedBy: String,
  uploadedAt: { type: Date, default: Date.now }
});

const UploadedFile =
  mongoose.models.UploadedFile ||
  mongoose.model("UploadedFile", uploadedFileSchema);

/* =========================
   AUTH MIDDLEWARE
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
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   MULTER CONFIG (SAFE)
========================= */
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (_, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Only PDF files allowed"));
    }
    cb(null, true);
  }
});

/* =========================
   UPLOAD ROUTE
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

    res.json({ success: true, file });

  } catch (err) {
    console.error("UPLOAD ERROR:", err.message);
    res.status(500).json({ message: "Upload failed" });
  }
});

module.exports = router;
