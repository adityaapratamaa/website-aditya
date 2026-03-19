const express = require("express")
const mysql = require("mysql2")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

if (!process.env.MYSQLHOST) {
  console.error("❌ MYSQL ENV KOSONG!")
  process.exit(1)
}

// ================= CORS =================
app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
  credentials: true
}))

app.use(express.json())

// ================= SESSION =================
app.set("trust proxy", 1)
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

// ================= DATABASE (FIX FINAL BANGET) =================
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

// TEST CONNECTION
db.getConnection((err, conn) => {
  if (err) {
    console.error("❌ DB ERROR:", err)
  } else {
    console.log("✅ Database connected")
    conn.release()
  }
})
// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: "Isi semua field" })
  }

  db.query("SELECT * FROM auth_users WHERE username = ?", [username], async (err, result) => {
    if (err) {
      console.error("REGISTER ERROR:", err)
      return res.status(500).json({ error: err.message })
    }

    if (result.length > 0) {
      return res.json({ success: false, message: "Username sudah ada" })
    }

    const hash = await bcrypt.hash(password, 10)

    db.query(
      "INSERT INTO auth_users (username, password) VALUES (?, ?)",
      [username, hash],
      (err) => {
        if (err) {
          console.error("INSERT ERROR:", err)
          return res.status(500).json({ error: err.message })
        }
        res.json({ success: true })
      }
    )
  })
})

// ================= LOGIN =================
app.post("/login", (req, res) => {
  const { username, password } = req.body

  db.query("SELECT * FROM auth_users WHERE username = ?", [username], async (err, result) => {
    if (err) {
      console.error("LOGIN ERROR:", err)
      return res.status(500).json({ error: err.message })
    }

    if (!result || result.length === 0) {
      return res.json({ success: false })
    }

    const user = result[0]
    const match = await bcrypt.compare(password, user.password)

    if (match) {
      req.session.user = username
      res.json({ success: true })
    } else {
      res.json({ success: false })
    }
  })
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
app.post("/users", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("INSERT INTO users (name,email) VALUES (?,?)", [name, email], (err) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json({ success: true })
  })
})

app.get("/users", isAuth, (req, res) => {
  db.query("SELECT * FROM users", (err, data) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json(data)
  })
})

app.delete("/users/:id", isAuth, (req, res) => {
  db.query("DELETE FROM users WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json({ success: true })
  })
})

app.put("/users/:id", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("UPDATE users SET name=?,email=? WHERE id=?", [name, email, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json({ success: true })
  })
})

// ================= DEBUG =================
app.get("/debug-users", (req, res) => {
  db.query("SELECT * FROM auth_users", (err, data) => {
    if (err) {
      console.error("DEBUG ERROR:", err)
      return res.json({ error: err.message })
    }
    res.json(data)
  })
})

// ================= ROOT =================
app.get("/", (req, res) => {
  res.send("SERVER FINAL FIX 🚀")
})

// ================= START =================
const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log("Server jalan di port", PORT)
})