const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

app.set("trust proxy", 1)

app.use(cors({
  origin: ["https://website-aditya-one.vercel.app"],
  credentials: true
}))

app.use(express.json())

app.use(session({
  secret: "aditya-super-secret-key-2026",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: "none",
    httpOnly: true
  }
}))

// ===== DATABASE =====
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false }
})

// ===== TEST DB =====
;(async () => {
  try {
    await db.query("SELECT 1")
    console.log("✅ DB Connected")
  } catch (err) {
    console.error("❌ DB ERROR:", err.message)
  }
})()

// ===== AUTH =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body

  const [existing] = await db.query(
    "SELECT * FROM auth_users WHERE username = ?",
    [username]
  )

  if (existing.length > 0) {
    return res.json({ success: false })
  }

  const hash = await bcrypt.hash(password, 10)

  await db.query(
    "INSERT INTO auth_users (username, password) VALUES (?, ?)",
    [username, hash]
  )

  res.json({ success: true })
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body

  const [users] = await db.query(
    "SELECT * FROM auth_users WHERE username = ?",
    [username]
  )

  if (users.length === 0) return res.json({ success: false })

  const user = users[0]
  const match = await bcrypt.compare(password, user.password)

  if (!match) return res.json({ success: false })

  req.session.user = username
  res.json({ success: true })
})

app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.json({ user: null })
  }
  res.json({ user: req.session.user })
})

// ===== USERS CRUD =====
app.get("/users", async (req, res) => {
  const [data] = await db.query("SELECT * FROM users")
  res.json(data)
})

app.post("/users", async (req, res) => {
  const { name, email } = req.body

  await db.query(
    "INSERT INTO users (name, email) VALUES (?, ?)",
    [name, email]
  )

  res.json({ success: true })
})

// ===== DEBUG =====
app.get("/debug-users", async (req, res) => {
  const [data] = await db.query("SELECT * FROM auth_users")
  res.json(data)
})

// ===== START =====
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("Server jalan:", PORT))