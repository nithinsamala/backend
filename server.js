// index.js
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

dotenv.config();

const uploadRouter = require("./upload"); // keep upload.js in same folder

const app = express();
const PORT = process.env.PORT || 5000;

/* =========================
   CORS (ALLOW VERCEL + LOCAL)
========================= */
// For local dev + deployment: allow requests and credentials from frontend
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true
}));
app.options("*", cors());

/* =========================
   MIDDLEWARE
========================= */
app.use(express.json());
app.use(cookieParser());

/* =========================
   UPLOAD DIRECTORY
========================= */
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

/* =========================
   DB CONNECT
========================= */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error", err));

/* =========================
   MODELS
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
  // set secure cookie only in production
  const secureFlag = process.env.NODE_ENV === "production";
  res.cookie("token", token, {
    httpOnly: true,
    secure: secureFlag,
    sameSite: secureFlag ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
};

/* =========================
   AUTH MIDDLEWARE
========================= */
const checkToken = (req, res, next) => {
  try {
    const token = req.cookies?.token;
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
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });
    sendToken(res, generateToken(user._id));
    res.json({ success: true, user: { email: user.email } });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: "User already exists" });
    console.error(err);
    res.status(500).json({ message: "Signup failed" });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });
    sendToken(res, generateToken(user._id));
    res.json({ success: true, user: { email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
});

/* =========================
   AUTH CHECK
========================= */
app.get("/api/auth/check", checkToken, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json({ isAuthenticated: true, user: { email: user.email } });
});

/* =========================
   LOGOUT
========================= */
app.post("/api/logout", (req, res) => {
  const secureFlag = process.env.NODE_ENV === "production";
  res.clearCookie("token", { sameSite: secureFlag ? "none" : "lax", secure: secureFlag });
  res.json({ success: true });
});

/* =========================
   AI CHAT FROM PDF
   Accepts: { message: string, structured?: boolean }
   If structured=true, server uses a stronger system prompt to produce
   well organized markdown (Headings, bullets, summary, action items).
========================= */
app.post("/api/chat", checkToken, async (req, res) => {
  try {
    const { message, structured } = req.body;
    if (!message) return res.status(400).json({ reply: "Message required" });

    const UploadedFile =
      mongoose.models.UploadedFile ||
      mongoose.model("UploadedFile");

    const file = await UploadedFile
      .findOne({ uploadedBy: req.userId })
      .sort({ uploadedAt: -1 });

    if (!file) return res.json({ reply: "❌ Please upload a PDF first." });

    const filePath = path.join(UPLOAD_DIR, file.filename);
    if (!fs.existsSync(filePath)) return res.json({ reply: "❌ Uploaded file missing." });

    const pdfData = await pdfParse(fs.readFileSync(filePath));
    const context = (pdfData.text || "").slice(0, 6000);

    // Choose prompt based on structured flag
    const systemPrompt = structured
      ? `You are an expert assistant that MUST ONLY use the provided document text to answer.
Your output must be in Markdown and must include (in this order):
1) A single-line **Title**.
2) **Summary** (2-3 bullets).
3) **Key Points** (bullet list — max 10 items).
4) **Step-by-step** or **Procedure** section if applicable.
5) **Action Items** (clear, numbered steps a user can follow).
6) A short **One-line TL;DR** at the end.
If the document does not contain an answer, return exactly: "Answer not found in the provided document."
Do NOT invent facts. Keep answers concise and well-structured.`
      : `You are a document-based assistant. Answer using only the provided document text. If the answer cannot be found in the document, reply: "Answer not found in the provided document." Keep responses concise.`;

    const payload = {
      model: "openai/gpt-oss-20b",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Document:\n${context}\n\nQuestion:\n${message}` }
      ],
      temperature: 0,
      max_tokens: 700
    };

    const groqRes = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    const reply = groqRes.data?.choices?.[0]?.message?.content
      || "Answer not found in the provided document.";

    res.json({ reply });

  } catch (err) {
    console.error("AI ERROR:", err.response?.data || err.message);
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
