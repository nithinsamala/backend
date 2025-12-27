const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const path = require("path");
const axios = require("axios");
const pdfParse = require("pdf-parse");

const uploadRouter = require("./upload");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

/* =========================
   ENV CHECK
========================= */
console.log("🔍 ENV CHECK");
console.log("MONGODB_URI:", !!process.env.MONGODB_URI);
console.log("JWT_SECRET:", !!process.env.JWT_SECRET);
console.log("GROQ_API_KEY:", !!process.env.GROQ_API_KEY);

/* =========================
   CORS (SAFE FOR VERCEL)
========================= */
app.use(cors({
  origin: true,          // allow all vercel preview + prod
  credentials: true
}));
app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

/* =========================
   DB CONNECT
========================= */
mongoose.set("debug", true);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error");
    console.error(err);
  });

/* =========================
   USER MODEL (FIXED)
========================= */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  }
});

const User = mongoose.model("User", userSchema);

/* =========================
   JWT HELPERS
========================= */
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

const sendToken = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
};

/* =========================
   AUTH MIDDLEWARE
========================= */
const checkToken = (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   HEALTH CHECK
========================= */
app.get("/", (req, res) => {
  res.send("✅ Backend is running");
});

/* =========================
   SIGNUP (FINAL & SAFE)
========================= */
app.post("/api/signup", async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // ✅ normalize email
    email = email.trim().toLowerCase();

    const hashed = await bcrypt.hash(password, 12);

    const user = await User.create({
      email,
      password: hashed
    });

    const token = generateToken(user._id);
    sendToken(res, token);

    return res.json({
      success: true,
      user: { email: user.email }
    });

  } catch (err) {
    console.error("🔥 SIGNUP ERROR:", err);

    if (err.code === 11000) {
      return res.status(409).json({ message: "User already exists" });
    }

    return res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  try {
    let { email, password } = req.body;

    email = email.trim().toLowerCase();

    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user._id);
    sendToken(res, token);

    res.json({ success: true, user: { email: user.email } });

  } catch (err) {
    console.error("🔥 LOGIN ERROR:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* =========================
   AUTH CHECK
========================= */
app.get("/api/auth/check", checkToken, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json({
    isAuthenticated: true,
    user: { email: user.email }
  });
});

/* =========================
   LOGOUT
========================= */
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    secure: true,
    sameSite: "none",
        path: "/"   
  });
  res.json({ success: true });
});

/* =========================
   START SERVER
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
