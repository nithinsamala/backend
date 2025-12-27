const express = require("express");
const multer = require("multer");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const router = express.Router();

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
   AUTH
========================= */
const auth = (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   MULTER
========================= */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });

/* =========================
   🔥 MAIN FIX
   POST /api/uploads
========================= */
router.post("/", auth, upload.single("file"), async (req, res) => {
  if (!req.file)
    return res.status(400).json({ message: "No file uploaded" });

  const file = await UploadedFile.create({
    filename: req.file.filename,
    originalName: req.file.originalname,
    uploadedBy: req.userId
  });

  res.json({ success: true, file });
});

module.exports = router;
