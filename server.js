const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
  credentials: true
}))

app.use(express.json())

// 🔥 SESSION (FIXED)
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
  secure: false,
  sameSite: "lax"
}
}))

// 🔥 DATABASE
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// TEST DB
;(async () => {
  try {
    await db.query("SELECT 1")
    console.log("✅ DB Connected")
  } catch (err) {
    console.error("❌ DB ERROR:", err)
  }
})()

// ================= AUTH =================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body

    const [users] = await db.query(
      "SELECT * FROM auth_users WHERE username=?",
      [username]
    )

    if (users.length === 0) return res.json({ success: false })

    const match = await bcrypt.compare(password, users[0].password)
    if (!match) return res.json({ success: false })

    req.session.user = username
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/me", (req, res) => {
  res.json({ loggedIn: !!req.session.user, user: req.session.user })
})

// ================= USERS =================

// 🔥 GET USERS (FIXED)
app.get("/users", async (req, res) => {
  try {
    const [data] = await db.query("SELECT * FROM users ORDER BY id DESC")
    res.json(data)
  } catch (err) {
    console.error("GET ERROR:", err)
    res.status(500).json({ error: err.message })
  }
})

// 🔥 ADD USER (FIXED)
app.post("/users", async (req, res) => {
  try {
    const { name, email } = req.body

    if (!name || !email) {
      return res.status(400).json({ error: "Data kosong" })
    }

    const [result] = await db.query(
      "INSERT INTO users (name,email) VALUES (?,?)",
      [name, email]
    )

    res.json({ success: true, id: result.insertId })
  } catch (err) {
    console.error("INSERT ERROR:", err)
    res.status(500).json({ error: err.message })
  }
})

// 🔥 DELETE
app.delete("/users/:id", async (req, res) => {
  try {
    await db.query("DELETE FROM users WHERE id=?", [req.params.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// 🔥 UPDATE
app.put("/users/:id", async (req, res) => {
  try {
    const { name, email } = req.body

    await db.query(
      "UPDATE users SET name=?, email=? WHERE id=?",
      [name, email, req.params.id]
    )

    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// START
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("🚀 Server jalan:", PORT))