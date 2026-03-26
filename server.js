require("dotenv").config();
const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI);

// ===== MODELS =====
const User = mongoose.model("User", new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  roles: [String]
}));

const Message = mongoose.model("Message", new mongoose.Schema({
  text: String,
  channelId: String,
  user: Object,
  createdAt: { type: Date, default: Date.now }
}));

// ===== AUTH MIDDLEWARE =====
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
};

// ===== ROUTES =====
app.post("/api/register", async (req, res) => {
  const hash = await require("bcrypt").hash(req.body.password, 10);
  const user = await User.create({
    username: req.body.username,
    password: hash,
    roles: ["user"]
  });
  res.json(user);
});

app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  const ok = user && await require("bcrypt").compare(req.body.password, user.password);

  if (!ok) return res.sendStatus(401);

  const token = jwt.sign(user.toObject(), process.env.JWT_SECRET);
  res.json({ token });
});

app.get("/api/messages/:channelId", auth, async (req, res) => {
  const msgs = await Message.find({ channelId: req.params.channelId });
  res.json(msgs);
});

// ===== SERVER =====
const server = http.createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });

// ===== SOCKET AUTH =====
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error("auth"));
  }
});

// ===== SOCKET =====
io.on("connection", (socket) => {

  socket.on("join", (channel) => socket.join(channel));

  socket.on("message", async (msg) => {
    // ROLE CHECK
    if (!socket.user.roles.includes("user")) return;

    const saved = await Message.create({
      ...msg,
      user: socket.user
    });

    io.to(msg.channelId).emit("message", saved);
  });

});

server.listen(5000);