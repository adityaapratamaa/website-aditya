const express = require("express")
const mysql = require("mysql2")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

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

// ================= DATABASE (FIX RAILWAY) =================
const db = mysql.createPool({
  uri: "mysql://root:ZJVcIRKGGXzPCRIrCGqbGhENEoJCFWaZ@autorack.proxy.rlwy.net:51186/railway",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

// ================= MIDDLEWARE =================
function isAuth(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    res.status(401).json({ message: "Unauthorized" })
  }
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: "Username & password wajib diisi" })
  }

  db.query("SELECT * FROM auth_users WHERE username = ?", [username], async (err, result) => {
    if (err) {
      console.error("REGISTER ERROR:", err)
      return res.status(500).json({ error: err.message })
    }

    if (result.length > 0) {
      return res.json({ success: false, message: "Username sudah ada" })
    }

    try {
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
    } catch (error) {
      res.status(500).json({ error: "Hash error" })
    }
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

    try {
      const match = await bcrypt.compare(password, user.password)

      if (match) {
        req.session.user = username
        res.json({ success: true })
      } else {
        res.json({ success: false })
      }
    } catch (error) {
      res.status(500).json({ error: "Compare error" })
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

// ================= CRUD USERS =================
app.post("/users", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("INSERT INTO users (name,email) VALUES (?,?)", [name, email], (err) => {
    if (err) {
      console.error("INSERT USER ERROR:", err)
      return res.status(500).json({ error: err.message })
    }
    res.json({ success: true })
  })
})

app.get("/users", isAuth, (req, res) => {
  db.query("SELECT * FROM users", (err, data) => {
    if (err) {
      console.error("GET USERS ERROR:", err)
      return res.status(500).json({ error: err.message })
    }
    res.json(data)
  })
})

app.delete("/users/:id", isAuth, (req, res) => {
  db.query("DELETE FROM users WHERE id=?", [req.params.id], (err) => {
    if (err) {
      console.error("DELETE ERROR:", err)
      return res.status(500).json({ error: err.message })
    }
    res.json({ success: true })
  })
})

app.put("/users/:id", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("UPDATE users SET name=?,email=? WHERE id=?", [name, email, req.params.id], (err) => {
    if (err) {
      console.error("UPDATE ERROR:", err)
      return res.status(500).json({ error: err.message })
    }
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
  res.send("SERVER HIDUP 🚀")
})

// ================= START =================
const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log("Server jalan di port", PORT)
})