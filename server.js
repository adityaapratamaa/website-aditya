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

app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // 🔥 WAJIB HTTPS
    sameSite: "none"     // 🔥 WAJIB CROSS DOMAIN
  }
}))

// DATABASE
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// ================= MIDDLEWARE AUTH =================
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

    req.session.user = username
    res.json({ success: true })

  } catch {
    res.status(500).json({ success: false })
  }
})

// ================= SESSION =================
app.get("/me", (req, res) => {
  res.json({ loggedIn: !!req.session.user })
})

// ================= LOGOUT =================
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true })
  })
})

// ================= USERS (PROTECTED) =================
app.get("/users", isAuth, async (req, res) => {
  const [data] = await db.query("SELECT * FROM users ORDER BY id DESC")
  res.json(data)
})

app.post("/users", isAuth, async (req, res) => {
  const { name, email } = req.body
  const [result] = await db.query(
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

// START
app.listen(process.env.PORT || 3000)