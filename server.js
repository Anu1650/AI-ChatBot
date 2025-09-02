import express from "express";
import bodyParser from "body-parser";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import OpenAI from "openai";
import bcrypt from "bcrypt";
import session from "express-session";
import nodemailer from "nodemailer";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// --- Middleware ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: true,
  })
);

// --- OpenAI client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// --- Database folders ---
const usersFolder = path.join("./database/users");
const chatsFolder = path.join("./database/chats");
[usersFolder, chatsFolder].forEach((folder) => {
  if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
});

// --- Helper functions ---
const loadUser = (email) => {
  const file = path.join(usersFolder, `${email}.json`);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : null;
};

const saveUser = (user) => {
  fs.writeFileSync(path.join(usersFolder, `${user.email}.json`), JSON.stringify(user, null, 2));
};

const loadChats = (email) => {
  const file = path.join(chatsFolder, `${email}.json`);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : [];
};

const saveChats = (email, history) => {
  fs.writeFileSync(path.join(chatsFolder, `${email}.json`), JSON.stringify(history, null, 2));
};

// --- Middleware: Admin check ---
const isAdmin = (req, res, next) => {
  if (req.session.userEmail === process.env.ADMIN_EMAIL) return next();
  res.status(403).send("Access denied. Admins only.");
};

// --- Routes ---
// Simple JSON login/register pages since no views
app.get("/", (req, res) => res.send({ message: "Use POST /login or /register with email & password" }));

// Login handler
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = loadUser(email);
  if (!user) return res.status(404).send({ error: "Email not found! Please register." });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).send({ error: "Incorrect password!" });

  req.session.userEmail = email;
  res.send({ message: `Login successful as ${email}`, redirect: email === process.env.ADMIN_EMAIL ? "/admin/dashboard" : "/chat" });
});

// Register handler
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (loadUser(email)) return res.status(400).send({ error: "Email already exists!" });

  const hashedPassword = await bcrypt.hash(password, 10);
  saveUser({ name, email, password: hashedPassword });
  saveChats(email, []);
  req.session.userEmail = email;

  res.send({ message: `Registered successfully as ${email}`, redirect: "/chat" });
});

// Chat page (JSON)
app.get("/chat", (req, res) => {
  if (!req.session.userEmail) return res.status(401).send({ error: "Not logged in" });
  const user = loadUser(req.session.userEmail);
  const history = loadChats(user.email);
  res.send({ message: `Welcome back, ${user.name}!`, history });
});

// Handle chat messages
app.post("/chat", async (req, res) => {
  try {
    const { message } = req.body;
    const email = req.session.userEmail;
    if (!email) return res.status(401).send({ error: "User not logged in" });

    const user = loadUser(email);
    const history = loadChats(email);

    const systemMessage = {
      role: "system",
      content: `You are chatting with ${user.name} (${user.email}). Remember previous chats and respond contextually.`,
    };

    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [systemMessage, ...history, { role: "user", content: message }],
    });

    const reply = response.choices[0].message.content;
    history.push({ role: "user", content: message });
    history.push({ role: "assistant", content: reply });
    saveChats(email, history);

    res.send({ reply, history });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Error with OpenAI API" });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.send({ message: "Logged out successfully" });
});

// --- Admin routes ---
app.get("/admin/dashboard", isAdmin, (req, res) => {
  const users = fs.readdirSync(usersFolder).map((f) => {
    const u = loadUser(f.replace(".json", ""));
    return { name: u.name, email: u.email };
  });
  res.send({ admin: req.session.userEmail, users });
});

// View user chats
app.get("/admin/user/:email", isAdmin, (req, res) => {
  const userEmail = req.params.email;
  const user = loadUser(userEmail);
  if (!user) return res.status(404).send({ error: "User not found" });
  res.send({ user, history: loadChats(userEmail) });
});

// Delete user chats
app.post("/admin/user/:email/delete-chats", isAdmin, (req, res) => {
  saveChats(req.params.email, []);
  res.send({ message: `Deleted chats for ${req.params.email}` });
});

// Delete user account
app.post("/admin/user/:email/delete-user", isAdmin, (req, res) => {
  const files = [
    path.join(usersFolder, `${req.params.email}.json`),
    path.join(chatsFolder, `${req.params.email}.json`),
  ];
  files.forEach((f) => fs.existsSync(f) && fs.unlinkSync(f));
  res.send({ message: `Deleted user ${req.params.email}` });
});

// Admin OTP flow
app.post("/admin/send-otp", isAdmin, async (req, res) => {
  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.adminOTP = otp;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: process.env.ADMIN_EMAIL,
    subject: "Admin Password Change OTP",
    text: `Your OTP is: ${otp}`,
  });

  res.send({ message: "OTP sent to admin email" });
});

app.post("/admin/verify-otp", isAdmin, async (req, res) => {
  const { otp, newPassword } = req.body;
  if (parseInt(otp) === req.session.adminOTP) {
    const adminUser = loadUser(process.env.ADMIN_EMAIL);
    adminUser.password = await bcrypt.hash(newPassword, 10);
    saveUser(adminUser);
    req.session.adminOTP = null;
    res.send({ message: "Admin password changed successfully!" });
  } else {
    res.status(400).send({ error: "Invalid OTP" });
  }
});

// --- Start server ---
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));
