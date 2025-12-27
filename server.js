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
   CORS (FINAL – NO ERRORS)
========================= */
app.use(cors({
  origin: true,          // 🔥 allow all origins dynamically
  credentials: true
}));
app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

/* =========================
   UPLOAD DIRECTORY
========================= */
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}
app.use("/uploads", express.static(UPLOAD_DIR));

/* =========================
   DB CONNECT
========================= */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

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
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
};

/* =========================
   SIGNUP
========================= */
app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "All fields required" });

  const exists = await User.findOne({ email });
  if (exists)
    return res.status(409).json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed });

  sendToken(res, generateToken(user._id));
  res.json({ success: true, user: { email: user.email } });
});

/* =========================
   LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user)
    return res.status(401).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ message: "Invalid credentials" });

  sendToken(res, generateToken(user._id));
  res.json({ success: true, user: { email: user.email } });
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
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", {
    secure: true,
    sameSite: "none"
  });
  res.json({ success: true });
});

/* =========================
   AI CHAT FROM PDF (CHAT PAGE)
========================= */
app.post("/api/chat", checkToken, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message)
      return res.status(400).json({ reply: "Message required" });

    const UploadedFile =
      mongoose.models.UploadedFile ||
      mongoose.model("UploadedFile");

    const file = await UploadedFile
      .findOne({ uploadedBy: req.userId })
      .sort({ uploadedAt: -1 });

    if (!file)
      return res.json({ reply: "❌ Please upload a PDF first." });

    const filePath = path.join(UPLOAD_DIR, file.filename);
    if (!fs.existsSync(filePath))
      return res.json({ reply: "❌ Uploaded file missing." });

    const pdfData = await pdfParse(fs.readFileSync(filePath));
    if (!pdfData.text?.trim())
      return res.json({ reply: "❌ No readable text in PDF." });

    const context = pdfData.text.slice(0, 6000);

    const groqRes = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "openai/gpt-oss-20b",
        messages: [
          {
            role: "system",
            content:
              "Answer ONLY from the document. If not found, say so."
          },
          {
            role: "user",
            content: `Document:\n${context}\n\nQuestion:\n${message}`
          }
        ],
        temperature: 0
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json({
      reply:
        groqRes.data.choices?.[0]?.message?.content ||
        "Answer not found in document."
    });

  } catch (err) {
    console.error("🔥 AI ERROR:", err.message);
    res.status(500).json({ reply: "AI error" });
  }
});

/* =========================
   UPLOAD ROUTES
========================= */
app.use("/api/uploads", uploadRouter);

/* =========================
   START SERVER
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
