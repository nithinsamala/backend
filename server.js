const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

/* 🔥 MISSING IMPORTS (CAUSE OF 500) */
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const pdfParse = require("pdf-parse");

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
    return res.status(401).json({ message: "Unauthorized" });
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
   AI CHAT FROM PDF
========================= */
app.post("/api/chat", checkToken, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ reply: "Message is required" });
    }

    /* GET LATEST UPLOADED FILE */
    const UploadedFile =
      mongoose.models.UploadedFile ||
      mongoose.model("UploadedFile");

    const file = await UploadedFile
      .findOne({ uploadedBy: req.userId })
      .sort({ uploadedAt: -1 });

    if (!file) {
      return res.json({ reply: "❌ Please upload a PDF first." });
    }

    const filePath = path.join(__dirname, "uploads", file.filename);

    if (!fs.existsSync(filePath)) {
      return res.json({ reply: "❌ Uploaded file not found on server." });
    }

    /* READ PDF */
    const pdfBuffer = fs.readFileSync(filePath);
    const pdfData = await pdfParse(pdfBuffer);

    if (!pdfData.text || !pdfData.text.trim()) {
      return res.json({ reply: "❌ No readable text found in the PDF." });
    }

    const context = pdfData.text.slice(0, 6000);

    /* GROQ REQUEST */
    const groqResponse = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "llama-3.3-70b-versatile",
        messages: [
          {
            role: "system",
            content: `
You are a strict document-based assistant.

RULES:
1. Answer ONLY using the provided document content.
2. If the answer is not present, reply exactly:
   "Answer not found in the provided document."
3. Use Markdown.
4. Use **bold headings** and bullet points.
5. Do NOT add outside knowledge.
`
          },
          {
            role: "user",
            content: `
Document Content:
${context}

User Question:
${message}
`
          }
        ],
        temperature: 0,
        max_tokens: 512
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    const reply =
      groqResponse.data?.choices?.[0]?.message?.content ||
      "Answer not found in the provided document.";

    return res.json({ reply });

  } catch (error) {
    console.error("🔥 CHAT ERROR:", error.response?.data || error.message);
    return res.status(500).json({
      reply: "❌ Failed to answer from the document."
    });
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
