const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

const uploadRouter = require("./upload");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

/* =========================
   MIDDLEWARE
========================= */
app.use(cors({
  origin: true,
  credentials: true
}));
app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

/* =========================
   DB
========================= */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error", err));

/* =========================
   USER MODEL
========================= */
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

/* =========================
   JWT HELPERS
========================= */
const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });

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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   BASIC ROUTE
========================= */
app.get("/", (req, res) => {
  res.send("✅ Backend running");
});

/* =========================
   AUTH ROUTES
========================= */
app.post("/api/signup", async (req, res) => {
  try {
    let { email, password } = req.body;
    email = email.toLowerCase();

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });

    sendToken(res, generateToken(user._id));
    res.json({ success: true });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ message: "User exists" });
    res.status(500).json({ message: "Signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: "Invalid credentials" });

  sendToken(res, generateToken(user._id));
  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", {
    secure: true,
    sameSite: "none"
  });
  res.json({ success: true });
});

app.get("/api/auth/check", checkToken, (req, res) => {
  res.json({ isAuthenticated: true });
});

/* =========================
   🔥 CHAT ROUTE (YOU ASKED)
========================= */
app.post("/api/chat", checkToken, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message)
      return res.status(400).json({ message: "Message required" });

    // 🔹 TEMP DUMMY RESPONSE
    // Later you can connect Groq / OpenAI / Gemini here
    const aiReply = `AI received: "${message}"`;

    res.json({
      success: true,
      reply: aiReply
    });
  } catch (err) {
    res.status(500).json({ message: "Chat failed" });
  }
});

/* =========================
   UPLOAD ROUTER
========================= */
app.use("/api/uploads", uploadRouter);

/* =========================
   START
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on ${PORT}`);
});
