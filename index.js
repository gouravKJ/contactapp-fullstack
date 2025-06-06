const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));

// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String
});

const contactSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  name: String,
  phone: String,
  email: String
});

const User = mongoose.model("User", userSchema);
const Contact = mongoose.model("Contact", contactSchema);

// Routes

// Register
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashed });
    await newUser.save();
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.json({ error: "Registration failed" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const found = await User.findOne({ email });
  if (!found) return res.json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, found.password);
  if (!match) return res.json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: found._id }, process.env.JWT_SECRET);
  res.json({ token });
});

// Middleware
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(auth, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Profile
app.get("/profile", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// Add contact
app.post("/contacts", verifyToken, async (req, res) => {
  const { name, phone, email } = req.body;
  const contact = new Contact({ userId: req.user.id, name, phone, email });
  await contact.save();
  res.json(contact);
});

// Get contacts
app.get("/contacts", verifyToken, async (req, res) => {
  const contacts = await Contact.find({ userId: req.user.id });
  res.json(contacts);
});

// Delete contact
app.delete("/contacts/:id", verifyToken, async (req, res) => {
  await Contact.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ message: "Contact deleted" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
