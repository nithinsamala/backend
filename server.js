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
   ENV DEBUG (PRINT EVERYTHING)
========================= */
console.log("🔍 ENV CHECK");
console.log("MONGODB_URI exists:", !!process.env.MONGODB_URI);
console.log("JWT_SECRET exists:", !!process.env.JWT_SECRET);
console.log("GROQ_API_KEY exists:", !!process.env.GROQ_API_KEY);

/* =========================
   CORS DEBUG
========================= */
app.use((req, res, next) => {
  console.log("➡️ Incoming:", req.method, req.originalUrl);
  console.log("➡️ Origin:", req.headers.origin);
  next();
});

app.use(cors({
  origin: true,
  credentials: true
}));
app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

/* =========================
   DB CONNECT (DEBUG)
========================= */
mongoose.set("debug", true);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Connection Failed");
    console.error(err);
  });

/* =========================
   USER MODEL
========================= */
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

/* =========================
   JWT HELPERS (DEBUG)
========================= */
const generateToken = (id) => {
  console.log("🔑 Generating JWT for user:", id);
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

const sendToken = (res, token) => {
  console.log("🍪 Setting auth cookie");
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
};

/* =========================
   AUTH MIDDLEWARE (DEBUG)
========================= */
const checkToken = (req, res, next) => {
  try {
    console.log("🔍 Checking auth cookie");
    const token = req.cookies.token;
    console.log("Token present:", !!token);

    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("JWT decoded:", decoded);

    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error("❌ Auth error:", err.message);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   SIGNUP (FULL DEBUG)
========================= */
app.post("/api/signup", async (req, res) => {
  try {
    console.log("Signup body:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });

    const token = generateToken(user._id);
    sendToken(res, token);

    res.json({
      success: true,
      user: { email: user.email }
    });

  } catch (err) {
    console.error("🔥 SIGNUP ERROR:", err);
    res.status(500).json({ message: "Signup failed" });
  }
});

  


/* =========================
   LOGIN (DEBUG)
========================= */
app.post("/api/login", async (req, res) => {
  console.log("🟢 LOGIN API HIT");
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    console.log("User found:", !!user);

    if (!user)
      return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    console.log("Password match:", match);

    if (!match)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user._id);
    sendToken(res, token);

    res.json({ success: true, user: { email: user.email } });

  } catch (err) {
    console.error("🔥 LOGIN ERROR");
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* =========================
   AUTH CHECK (DEBUG)
========================= */
app.get("/api/auth/check", checkToken, async (req, res) => {
  console.log("🟢 AUTH CHECK");
  const user = await User.findById(req.userId);
  res.json({ isAuthenticated: true, user: { email: user.email } });
});

/* =========================
   START SERVER
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
