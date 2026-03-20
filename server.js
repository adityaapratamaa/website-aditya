const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

// 🔥 WAJIB UNTUK RAILWAY / VERCEL
app.set("trust proxy", 1)

// CORS
app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
  credentials: true
}))

app.use(express.json())

// SESSION (FIX ANTI GAGAL)
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false,
  proxy: true, // 🔥 penting
  cookie: {
    secure: true,      // wajib https
    sameSite: "none"   // wajib cross domain
  }
}))

// DATABASE
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// ================= AUTH MIDDLEWARE =================
function isAuth(req, res, next){
  if(!req.session.user){
    return res.status(401).json({ error: "Unauthorized" })
  }
  next()
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.json({ success: false, message: "Data tidak lengkap" })
    }

    const [existing] = await db.query(
      "SELECT * FROM auth_users WHERE username=?",
      [username]
    )

    if (existing.length > 0) {
      return res.json({ success: false, message: "Username sudah dipakai" })
    }

    const hashed = await bcrypt.hash(password, 10)

    await db.query(
      "INSERT INTO auth_users (username, password) VALUES (?,?)",
      [username, hashed]
    )

    res.json({ success: true })

  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false })
  }
})

// ================= LOGIN =================
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

    // 🔥 SET SESSION
    req.session.user = {
      username: users[0].username
    }

    res.json({ success: true })

  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false })
  }
})

// ================= CEK SESSION =================
app.get("/me", (req, res) => {
  if(req.session.user){
    res.json({
      loggedIn: true,
      user: req.session.user
    })
  } else {
    res.json({ loggedIn: false })
  }
})

// ================= LOGOUT =================
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid")
    res.json({ success: true })
  })
})

// ================= USERS =================
app.get("/users", isAuth, async (req, res) => {
  const [data] = await db.query("SELECT * FROM users ORDER BY id DESC")
  res.json(data)
})

app.post("/users", isAuth, async (req, res) => {
  const { name, email } = req.body
  await db.query(
    "INSERT INTO users (name,email) VALUES (?,?)",
    [name, email]
  )
  res.json({ success: true })
})

app.delete("/users/:id", isAuth, async (req, res) => {
  await db.query("DELETE FROM users WHERE id=?", [req.params.id])
  res.json({ success: true })
})

app.put("/users/:id", isAuth, async (req, res) => {
  const { name, email } = req.body
  await db.query(
    "UPDATE users SET name=?, email=? WHERE id=?",
    [name, email, req.params.id]
  )
  res.json({ success: true })
})

// START SERVER
app.listen(process.env.PORT || 3000, () => {
  console.log("Server jalan...")
})