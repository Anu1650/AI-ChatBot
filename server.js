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
app.set("view engine", "ejs");
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: true,
  })
);

// --- OpenAI client ---
const openaiApiKey = process.env.OPENAI_API_KEY;
if (!openaiApiKey) console.warn("⚠️  OPENAI_API_KEY is missing in .env");
const client = new OpenAI({ apiKey: openaiApiKey });

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
  res.redirect("/");
};

// --- Routes ---
// Login/Register page
app.get("/", (req, res) => res.render("login", { error: null }));

// Login handler
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = loadUser(email);
  if (!user) return res.render("login", { error: "Email not found! Please register." });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.render("login", { error: "Incorrect password!" });

  req.session.userEmail = email;
  res.redirect(email === process.env.ADMIN_EMAIL ? "/admin/dashboard" : "/chat");
});

// Register handler
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (loadUser(email)) return res.render("login", { error: "Email already exists!" });

  const hashedPassword = await bcrypt.hash(password, 10);
  saveUser({ name, email, password: hashedPassword });
  saveChats(email, []); // Initialize empty chat history

  req.session.userEmail = email;
  res.redirect("/chat");
});

// Chat page
app.get("/chat", (req, res) => {
  if (!req.session.userEmail) return res.redirect("/");
  const user = loadUser(req.session.userEmail);
  const history = loadChats(user.email);
  res.render("chat", { user, history, message: `Welcome back, ${user.name}!` });
});

// Handle chat messages
app.post("/chat", async (req, res) => {
  try {
    const { message } = req.body;
    const email = req.session.userEmail;
    if (!email) return res.status(400).send("User not logged in");

    const user = loadUser(email);
    const history = loadChats(email);

    const systemMessage = {
      role: "system",
      content: `You are chatting with ${user.name} (${user.email}). Remember all previous chats and respond contextually.`,
    };

    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [systemMessage, ...history, { role: "user", content: message }],
    });

    const reply = response.choices[0].message.content;
    history.push({ role: "user", content: message });
    history.push({ role: "assistant", content: reply });
    saveChats(email, history);

    res.json({ reply, history });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error with OpenAI API");
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// --- Admin routes ---
// Admin dashboard
app.get("/admin/dashboard", isAdmin, (req, res) => {
  const users = fs.readdirSync(usersFolder).map((f) => {
    const u = loadUser(f.replace(".json", ""));
    return { name: u.name, email: u.email };
  });
  res.render("admin_dashboard", { users, adminEmail: req.session.userEmail });
});

// Admin user chats
app.get("/admin/user/:email", isAdmin, (req, res) => {
  const userEmail = req.params.email;
  const user = loadUser(userEmail);
  if (!user) return res.send("User not found");
  res.render("admin_user_chats", { user, history: loadChats(userEmail) });
});

// Admin delete chats
app.post("/admin/user/:email/delete-chats", isAdmin, (req, res) => {
  saveChats(req.params.email, []);
  res.redirect(`/admin/user/${req.params.email}`);
});

// Admin delete user
app.post("/admin/user/:email/delete-user", isAdmin, (req, res) => {
  const userFile = path.join(usersFolder, `${req.params.email}.json`);
  const chatFile = path.join(chatsFolder, `${req.params.email}.json`);
  [userFile, chatFile].forEach((f) => fs.existsSync(f) && fs.unlinkSync(f));
  res.redirect("/admin/dashboard");
});

// Admin OTP password change
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

  res.redirect("/admin/change-password");
});

app.get("/admin/change-password", isAdmin, (req, res) => res.render("admin_change_password"));

app.post("/admin/verify-otp", isAdmin, async (req, res) => {
  const { otp, newPassword } = req.body;
  if (parseInt(otp) === req.session.adminOTP) {
    const adminUser = loadUser(process.env.ADMIN_EMAIL);
    adminUser.password = await bcrypt.hash(newPassword, 10);
    saveUser(adminUser);
    req.session.adminOTP = null;
    res.send("Password changed successfully!");
  } else {
    res.send("Invalid OTP. Try again.");
  }
});

// --- Start server ---
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));
