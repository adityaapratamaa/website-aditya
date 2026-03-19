const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

app.set("trust proxy", 1)

app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
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
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24
  }
}))

// ================= DATABASE FINAL =================
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false }
})

// ================= TEST DB =================
;(async () => {
  try {
    await db.query("SELECT 1")
    console.log("✅ Database connected")
  } catch (err) {
    console.error("❌ DB ERROR:", err.message)
  }
})()

function isAuth(req, res, next) {
  if (req.session.user) return next()
  res.status(401).json({ message: "Unauthorized" })
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({ error: "Isi semua field" })
    }

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

  } catch (err) {
    console.error(err)
    res.status(500).json({ error: "Server error" })
  }
})

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body

    const [users] = await db.query(
      "SELECT * FROM auth_users WHERE username = ?",
      [username]
    )

    if (users.length === 0) {
      return res.json({ success: false })
    }

    const user = users[0]
    const match = await bcrypt.compare(password, user.password)

    if (!match) return res.json({ success: false })

    req.session.user = username
    res.json({ success: true })

  } catch (err) {
    res.status(500).json({ error: "Server error" })
  }
})

// ================= DEBUG =================
app.get("/debug-users", async (req, res) => {
  const [data] = await db.query("SELECT * FROM auth_users")
  res.json(data)
})

// ================= START =================
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("Server jalan:", PORT))