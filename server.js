const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

// ================= TRUST PROXY =================
app.set("trust proxy", 1)

// ================= CORS =================
app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
  credentials: true
}))

app.use(express.json())

// ================= SESSION =================
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

// ================= DATABASE =================
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,

  ssl: {
    rejectUnauthorized: false
  },

  waitForConnections: true,
  connectionLimit: 10,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
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

// ================= AUTH MIDDLEWARE =================
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
    console.error("REGISTER ERROR:", err)
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

    if (!match) {
      return res.json({ success: false })
    }

    req.session.user = username

    res.json({ success: true })

  } catch (err) {
    console.error("LOGIN ERROR:", err)
    res.status(500).json({ error: "Server error" })
  }
})

// ================= CHECK AUTH =================
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user })
  } else {
    res.json({ loggedIn: false })
  }
})

// ================= LOGOUT =================
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true })
  })
})

// ================= CRUD =================
app.post("/users", isAuth, async (req, res) => {
  try {
    const { name, email } = req.body

    await db.query(
      "INSERT INTO users (name,email) VALUES (?,?)",
      [name, email]
    )

    res.json({ success: true })

  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get("/users", isAuth, async (req, res) => {
  try {
    const [data] = await db.query("SELECT * FROM users")
    res.json(data)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete("/users/:id", isAuth, async (req, res) => {
  try {
    await db.query("DELETE FROM users WHERE id=?", [req.params.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put("/users/:id", isAuth, async (req, res) => {
  try {
    const { name, email } = req.body

    await db.query(
      "UPDATE users SET name=?,email=? WHERE id=?",
      [name, email, req.params.id]
    )

    res.json({ success: true })

  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ================= DEBUG =================
app.get("/debug-users", async (req, res) => {
  try {
    const [data] = await db.query("SELECT * FROM auth_users")
    res.json(data)
  } catch (err) {
    res.json({ error: err.message })
  }
})

// ================= ROOT =================
app.get("/", (req, res) => {
  res.send("SERVER FINAL FIX 🚀")
})

// ================= KEEP ALIVE =================
setInterval(async () => {
  try {
    await db.query("SELECT 1")
    console.log("✅ DB KeepAlive OK")
  } catch (err) {
    console.error("❌ KeepAlive DB Error:", err.message)
  }
}, 5000)

// ================= START =================
const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log("Server jalan di port", PORT)
})